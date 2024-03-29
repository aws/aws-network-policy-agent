package manifest

import (
	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type ServiceBuilder struct {
	name        string
	namespace   string
	port        int32
	nodePort    int32
	protocol    v1.Protocol
	selector    map[string]string
	serviceType v1.ServiceType
}

func NewHTTPService() *ServiceBuilder {
	return &ServiceBuilder{
		port:        80,
		protocol:    v1.ProtocolTCP,
		selector:    map[string]string{},
		serviceType: v1.ServiceTypeClusterIP,
	}
}

func (s *ServiceBuilder) Name(name string) *ServiceBuilder {
	s.name = name
	return s
}

func (s *ServiceBuilder) Namespace(namespace string) *ServiceBuilder {
	s.namespace = namespace
	return s
}

func (s *ServiceBuilder) Port(port int32) *ServiceBuilder {
	s.port = port
	return s
}

func (s *ServiceBuilder) NodePort(nodePort int32) *ServiceBuilder {
	s.nodePort = nodePort
	return s
}

func (s *ServiceBuilder) Protocol(protocol v1.Protocol) *ServiceBuilder {
	s.protocol = protocol
	return s
}

func (s *ServiceBuilder) Selector(labelKey string, labelVal string) *ServiceBuilder {
	s.selector[labelKey] = labelVal
	return s
}

func (s *ServiceBuilder) ServiceType(serviceType v1.ServiceType) *ServiceBuilder {
	s.serviceType = serviceType
	return s
}

func (s *ServiceBuilder) Build() *v1.Service {
	return &v1.Service{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      s.name,
			Namespace: s.namespace,
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{{
				Name:       "",
				Protocol:   v1.ProtocolTCP,
				Port:       s.port,
				TargetPort: intstr.IntOrString{IntVal: s.port},
				NodePort:   s.nodePort,
			}},
			Selector: s.selector,
			Type:     s.serviceType,
		},
	}
}
