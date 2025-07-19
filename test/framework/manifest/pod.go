package manifest

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PodBuilder struct {
	namespace              string
	name                   string
	serviceAccountName     string
	container              v1.Container
	os                     string
	labels                 map[string]string
	annotations            map[string]string
	terminationGracePeriod int
	restartPolicy          v1.RestartPolicy
	nodeName               string
	volume                 []v1.Volume
}

func (p *PodBuilder) Build() *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        p.name,
			Namespace:   p.namespace,
			Labels:      p.labels,
			Annotations: p.annotations,
		},
		Spec: v1.PodSpec{
			NodeName:                      p.nodeName,
			ServiceAccountName:            p.serviceAccountName,
			Containers:                    []v1.Container{p.container},
			NodeSelector:                  map[string]string{"kubernetes.io/os": p.os},
			TerminationGracePeriodSeconds: aws.Int64(int64(p.terminationGracePeriod)),
			RestartPolicy:                 p.restartPolicy,
			Volumes:                       p.volume,
		},
	}
}

func NewDefaultPodBuilder() *PodBuilder {
	return &PodBuilder{
		namespace:              "default",
		name:                   "pod",
		container:              NewBusyBoxContainerBuilder().Build(),
		os:                     "linux",
		labels:                 map[string]string{},
		annotations:            map[string]string{},
		terminationGracePeriod: 10,
		restartPolicy:          v1.RestartPolicyNever,
		volume:                 []v1.Volume{},
	}
}

func (p *PodBuilder) Namespace(namespace string) *PodBuilder {
	p.namespace = namespace
	return p
}

func (p *PodBuilder) Name(name string) *PodBuilder {
	p.name = name
	return p
}

func (p *PodBuilder) Container(container v1.Container) *PodBuilder {
	p.container = container
	return p
}

func (p *PodBuilder) OS(os string) *PodBuilder {
	p.os = os
	return p
}

func (p *PodBuilder) RestartPolicy(policy v1.RestartPolicy) *PodBuilder {
	p.restartPolicy = policy
	return p
}

func (p *PodBuilder) AddLabel(labelkey string, labelValue string) *PodBuilder {
	p.labels[labelkey] = labelValue
	return p
}

func (p *PodBuilder) Annotations(annotations map[string]string) *PodBuilder {
	p.annotations = annotations
	return p
}

func (p *PodBuilder) ServiceAccount(serviceAccountName string) *PodBuilder {
	p.serviceAccountName = serviceAccountName
	return p
}

func (p *PodBuilder) TerminationGracePeriod(terminationGracePeriod int) *PodBuilder {
	p.terminationGracePeriod = terminationGracePeriod
	return p
}

func (p *PodBuilder) NodeName(nodeName string) *PodBuilder {
	p.nodeName = nodeName
	return p
}

func (p *PodBuilder) AddVolume(volume v1.Volume) *PodBuilder {
	p.volume = append(p.volume, volume)
	return p
}
