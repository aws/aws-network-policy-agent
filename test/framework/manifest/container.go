package manifest

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
)

type Container struct {
	name            string
	image           string
	imagePullPolicy v1.PullPolicy
	command         []string
	args            []string
	containerPorts  []v1.ContainerPort
	resources       v1.ResourceRequirements
	imageRepository string
	volumeMount     []v1.VolumeMount
}

func NewBusyBoxContainerBuilder() *Container {
	return &Container{
		name:            "busybox",
		image:           "e2e-test-images/busybox:1.29-4",
		imagePullPolicy: v1.PullIfNotPresent,
		command:         []string{"sleep", "3600"},
		args:            []string{},
		volumeMount:     []v1.VolumeMount{},
	}
}

func NewAgnHostContainerBuilder() *Container {
	return &Container{
		name:            "agnhost",
		image:           "e2e-test-images/agnhost:2.45",
		command:         []string{"/bin/sh", "-c"},
		imagePullPolicy: v1.PullIfNotPresent,
	}
}

func (c *Container) Name(name string) *Container {
	c.name = name
	return c
}

func (c *Container) Image(image string) *Container {
	c.image = image
	return c
}

func (c *Container) ImagePullPolicy(policy v1.PullPolicy) *Container {
	c.imagePullPolicy = policy
	return c
}

func (c *Container) Command(cmd []string) *Container {
	c.command = cmd
	return c
}

func (c *Container) Args(arg []string) *Container {
	c.args = arg
	return c
}

func (c *Container) AddContainerPort(containerPort v1.ContainerPort) *Container {
	c.containerPorts = append(c.containerPorts, containerPort)
	return c
}

func (c *Container) Resources(resource v1.ResourceRequirements) *Container {
	c.resources = resource
	return c
}

func (c *Container) ImageRepository(imageRepository string) *Container {
	c.imageRepository = fmt.Sprintf("%s/", imageRepository)
	return c
}

func (c *Container) AddVolumeMount(volumeMount v1.VolumeMount) *Container {
	c.volumeMount = append(c.volumeMount, volumeMount)
	return c
}

func (w *Container) Build() v1.Container {
	return v1.Container{
		Name:            w.name,
		Image:           fmt.Sprintf("%s%s", w.imageRepository, w.image),
		Command:         w.command,
		Args:            w.args,
		ImagePullPolicy: w.imagePullPolicy,
		Ports:           w.containerPorts,
		Resources:       w.resources,
		VolumeMounts:    w.volumeMount,
	}
}
