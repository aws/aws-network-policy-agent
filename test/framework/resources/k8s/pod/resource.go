package pod

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-network-policy-agent/test/framework/utils"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Manager interface {
	CreateAndWaitTillPodIsRunning(context context.Context, pod *v1.Pod, timeOut time.Duration) (*v1.Pod, error)
	CreateAndWaitTillPodIsCompleted(context context.Context, pod *v1.Pod) (*v1.Pod, error)
	DeleteAndWaitTillPodIsDeleted(context context.Context, pod *v1.Pod) error
	GetPodsWithLabel(context context.Context, namespace string, labelKey string, labelValue string) ([]v1.Pod, error)
	PatchPod(context context.Context, oldPod *v1.Pod, newPod *v1.Pod) error
	PodLogs(namespace string, name string) (string, error)
}

type defaultManager struct {
	k8sClient    client.Client
	k8sClientSet *kubernetes.Clientset
}

func NewManager(k8sClient client.Client, k8sclientSet *kubernetes.Clientset) Manager {
	return &defaultManager{
		k8sClient:    k8sClient,
		k8sClientSet: k8sclientSet,
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
