package pod

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Manager interface {
	CreateAndWaitTillPodIsRunning(context context.Context, pod *v1.Pod, timeOut time.Duration) (*v1.Pod, error)
	CreateAndWaitTillPodIsCompleted(context context.Context, pod *v1.Pod) (*v1.Pod, error)
	DeleteAndWaitTillPodIsDeleted(context context.Context, pod *v1.Pod) error
	GetPodsWithLabel(context context.Context, namespace string, labelKey string, labelValue string) ([]v1.Pod, error)
	PatchPod(context context.Context, oldPod *v1.Pod, newPod *v1.Pod) error
	PodLogs(namespace string, name string) (string, error)
	ExecInPod(namespace string, podName string, command []string) (string, error)
	ValidateConnection(namespace string, podName string, url string, ipFamily string) (string, error)
}

type defaultManager struct {
	k8sClient    client.Client
	k8sClientSet *kubernetes.Clientset
	restConfig   *rest.Config
}

func NewManager(k8sClient client.Client, k8sclientSet *kubernetes.Clientset, restConfig *rest.Config) Manager {
	return &defaultManager{
		k8sClient:    k8sClient,
		k8sClientSet: k8sclientSet,
		restConfig:   restConfig,
	}
}

func (d *defaultManager) CreateAndWaitTillPodIsRunning(ctx context.Context, pod *v1.Pod, timeOut time.Duration) (*v1.Pod, error) {
	err := d.k8sClient.Create(ctx, pod)
	if err != nil {
		return nil, err
	}

	updatedPod := &v1.Pod{}
	err = wait.PollUntilContextTimeout(ctx, utils.PollIntervalShort, timeOut, true, func(context.Context) (done bool, err error) {
		err = d.k8sClient.Get(ctx, utils.NamespacedName(pod), updatedPod)
		if err != nil {
			return true, err
		}
		return isPodReady(updatedPod), nil
	})

	return updatedPod, err
}

func (d *defaultManager) CreateAndWaitTillPodIsCompleted(ctx context.Context, pod *v1.Pod) (*v1.Pod, error) {
	err := d.k8sClient.Create(ctx, pod)
	if err != nil {
		return nil, err
	}

	updatedPod := &v1.Pod{}
	err = wait.PollUntilContextCancel(ctx, utils.PollIntervalShort, true, func(context.Context) (done bool, err error) {
		err = d.k8sClient.Get(ctx, utils.NamespacedName(pod), updatedPod)
		if err != nil {
			return true, err
		}
		if isPodCompleted(updatedPod) {
			return true, nil
		}
		if isPodFailed(updatedPod) {
			return true, fmt.Errorf("pod failed to start")
		}
		return false, nil
	})

	return updatedPod, err
}

func (d *defaultManager) GetPodsWithLabel(context context.Context, namespace string,
	labelKey string, labelValue string) ([]v1.Pod, error) {

	podList := &v1.PodList{}
	err := d.k8sClient.List(context, podList, &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{labelKey: labelValue}),
		Namespace:     namespace,
	})

	return podList.Items, err
}

func (d *defaultManager) DeleteAndWaitTillPodIsDeleted(ctx context.Context, pod *v1.Pod) error {
	if err := d.k8sClient.Delete(ctx, pod); err != nil {
		return client.IgnoreNotFound(err)
	}

	observedPod := &v1.Pod{}
	return wait.PollUntilContextCancel(ctx, utils.PollIntervalShort, true, func(context.Context) (done bool, err error) {
		err = d.k8sClient.Get(ctx, client.ObjectKeyFromObject(pod), observedPod)
		if errors.IsNotFound(err) {
			return true, nil
		}
		return false, err
	})
}

func (d *defaultManager) DeleteAllPodsForcefully(context context.Context,
	podLabelKey string, podLabelVal string) error {

	podList := &v1.PodList{}
	d.k8sClient.List(context, podList, &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{podLabelKey: podLabelVal}),
	})

	if len(podList.Items) == 0 {
		return fmt.Errorf("no pods found with label %s:%s", podLabelKey, podLabelVal)
	}

	gracePeriod := int64(0)
	for _, pod := range podList.Items {
		err := d.k8sClient.Delete(context, &pod, &client.DeleteOptions{
			GracePeriodSeconds: &gracePeriod,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *defaultManager) PatchPod(context context.Context, oldPod *v1.Pod, newPod *v1.Pod) error {
	return d.k8sClient.Patch(context, newPod, client.MergeFrom(oldPod))
}

func isPodReady(pod *v1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Status == v1.ConditionTrue && condition.Type == v1.PodReady {
			return true
		}
	}
	return false
}

func isPodCompleted(pod *v1.Pod) bool {
	return pod.Status.Phase == v1.PodSucceeded
}

func isPodFailed(pod *v1.Pod) bool {
	return pod.Status.Phase == v1.PodFailed
}

func (d *defaultManager) PodLogs(namespace string, name string) (string, error) {
	podLogOpts := v1.PodLogOptions{}
	req := d.k8sClientSet.CoreV1().Pods(namespace).GetLogs(name, &podLogOpts)

	podLogs, err := req.Stream(context.Background())
	if err != nil {
		return "error in opening stream", err
	}
	defer podLogs.Close()

	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, podLogs)

	if err != nil {
		return "error in copy information from podLogs to buf", err
	}
	return buf.String(), nil
}

func (d *defaultManager) ExecInPod(namespace string, podName string, command []string) (string, error) {
	req := d.k8sClientSet.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec")

	req.VersionedParams(&v1.PodExecOptions{
		Command: command,
		Stdout:  true,
		Stderr:  true,
	}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(d.restConfig, "POST", req.URL())
	if err != nil {
		return "", err
	}

	var stdout, stderr bytes.Buffer
	err = exec.StreamWithContext(context.TODO(), remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})

	if err != nil {
		return "", fmt.Errorf("exec failed: %v, stderr: %s", err, stderr.String())
	}

	result := stdout.String()
	if stderr.Len() > 0 {
		result += "\nSTDERR: " + stderr.String()
	}

	return strings.TrimSpace(result), nil
}

func (d *defaultManager) ValidateConnection(namespace string, podName string, url string, ipFamily string) (string, error) {
	req := d.k8sClientSet.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec")

	curlCmd := []string{"curl", "-s", "--max-time", "10", "-w", "\nURL:%{url_effective}\nHTTP_CODE:%{http_code}"}

	if ipFamily == "IPv6" {
		curlCmd = append(curlCmd, "-6")
	}

	if strings.HasPrefix(url, "https://") {
		curlCmd = append(curlCmd, "-k")
	}

	curlCmd = append(curlCmd, url)

	req.VersionedParams(&v1.PodExecOptions{
		Command: curlCmd,
		Stdout:  true,
		Stderr:  true,
	}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(d.restConfig, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("failed to create executor: %v", err)
	}

	var stdout, stderr bytes.Buffer
	execErr := exec.StreamWithContext(context.TODO(), remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})

	stderrStr := stderr.String()
	stdoutStr := stdout.String()

	// Check for HTTP code 000 which indicates connection failure
	if strings.Contains(stdoutStr, "HTTP_CODE:000") {
		return stdoutStr, fmt.Errorf("connection to %s failed: HTTP code 000 (connection blocked or failed)", url)
	}

	// Check for curl connection failures in stderr
	if strings.Contains(stderrStr, "Failed to connect") ||
		strings.Contains(stderrStr, "Connection timed out") ||
		strings.Contains(stderrStr, "Operation timed out") ||
		strings.Contains(stderrStr, "Could not resolve host") ||
		strings.Contains(stderrStr, "Connection refused") {
		return stdoutStr, fmt.Errorf("connection to %s failed: %s", url, stderrStr)
	}

	// If exec itself failed and we have stderr, return error
	if execErr != nil && stderrStr != "" {
		return stdoutStr, fmt.Errorf("connection to %s failed: %v, stderr: %s", url, execErr, stderrStr)
	}

	return strings.TrimSpace(stdoutStr), nil
}
