package manifest

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type DeploymentBuilder struct {
	namespace              string
	name                   string
	replicas               int
	os                     string
	container              corev1.Container
	labels                 map[string]string
	terminationGracePeriod int
	nodeSelector           map[string]string
	volume                 []corev1.Volume
}

func NewDefaultDeploymentBuilder() *DeploymentBuilder {
	return &DeploymentBuilder{
		namespace:              "default",
		name:                   "deployment",
		replicas:               2,
		nodeSelector:           map[string]string{"kubernetes.io/os": "linux"},
		os:                     "linux",
		container:              NewBusyBoxContainerBuilder().Build(),
		labels:                 map[string]string{},
		terminationGracePeriod: 0,
		volume:                 []corev1.Volume{},
	}
}

func (d *DeploymentBuilder) Namespace(namespace string) *DeploymentBuilder {
	d.namespace = namespace
	return d
}

func (d *DeploymentBuilder) TerminationGracePeriod(tg int) *DeploymentBuilder {
	d.terminationGracePeriod = tg
	return d
}

func (d *DeploymentBuilder) Name(name string) *DeploymentBuilder {
	d.name = name
	return d
}

func (d *DeploymentBuilder) Replicas(replicas int) *DeploymentBuilder {
	d.replicas = replicas
	return d
}

func (d *DeploymentBuilder) OS(os string) *DeploymentBuilder {
	d.os = os
	return d
}

func (d *DeploymentBuilder) Container(container corev1.Container) *DeploymentBuilder {
	d.container = container
	return d
}

func (d *DeploymentBuilder) AddLabel(labelKey string, labelValue string) *DeploymentBuilder {
	d.labels[labelKey] = labelValue
	return d
}

func (d *DeploymentBuilder) NodeSelector(selector map[string]string) *DeploymentBuilder {
	d.nodeSelector = selector
	return d
}

func (d *DeploymentBuilder) AddVolume(volume corev1.Volume) *DeploymentBuilder {
	d.volume = append(d.volume, volume)
	return d
}

func (d *DeploymentBuilder) Build() *v1.Deployment {
	return &v1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      d.name,
			Namespace: d.namespace,
		},
		Spec: v1.DeploymentSpec{
			Replicas: aws.Int32(int32(d.replicas)),
			Selector: &metav1.LabelSelector{
				MatchLabels: d.labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: d.labels,
				},
				Spec: corev1.PodSpec{
					Containers:                    []corev1.Container{d.container},
					NodeSelector:                  d.nodeSelector,
					TerminationGracePeriodSeconds: aws.Int64(int64(d.terminationGracePeriod)),
					Volumes:                       d.volume,
				},
			},
		},
	}
}
