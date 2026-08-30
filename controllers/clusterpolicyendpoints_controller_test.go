package controllers

import (
	"context"
	"testing"

	policyendpoint "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	mock_client "github.com/aws/aws-network-policy-agent/mocks/controller-runtime/client"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/golang/mock/gomock"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestClusterPolicyEndpointReconcile(t *testing.T) {
	namespace := "my-namespace"
	nodeIp := "1.1.1.1"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("Reconcile cleans up non-local pod identifiers on pod churn and CPE delete", func(t *testing.T) {
		mockClient := mock_client.NewMockClient(ctrl)
		reconciler := NewClusterPolicyEndpointsReconciler(mockClient, nodeIp, &ebpf.MockBpfClient{})

		remotePod1 := policyendpoint.PodEndpoint{
			HostIP:    "2.2.2.2",
			PodIP:     "10.1.2.1",
			Name:      "deployment1rs-1",
			Namespace: namespace,
		}
		remotePod2 := policyendpoint.PodEndpoint{
			HostIP:    "2.2.2.2",
			PodIP:     "10.1.2.2",
			Name:      "deployment2rs-1",
			Namespace: namespace,
		}

		currentCPE := getClusterPolicyEndpoint("allow-all-cnp", []policyendpoint.PodEndpoint{remotePod1})
		cpeDeleted := false

		mockClient.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(ctx context.Context, key types.NamespacedName, cpe *policyendpoint.ClusterPolicyEndpoint, opts ...client.GetOption) error {
				if cpeDeleted {
					return apierrors.NewNotFound(schema.GroupResource{Group: policyendpoint.GroupVersion.Group, Resource: ""}, "")
				}
				*cpe = currentCPE
				return nil
			},
		).AnyTimes()

		mockClient.EXPECT().List(gomock.Any(), gomock.AssignableToTypeOf(&policyendpoint.ClusterPolicyEndpointList{}), gomock.Any()).DoAndReturn(
			func(ctx context.Context, list *policyendpoint.ClusterPolicyEndpointList, opts ...*client.ListOptions) error {
				if cpeDeleted {
					*list = policyendpoint.ClusterPolicyEndpointList{}
				} else {
					*list = policyendpoint.ClusterPolicyEndpointList{
						Items: []policyendpoint.ClusterPolicyEndpoint{currentCPE},
					}
				}
				return nil
			},
		).AnyTimes()

		req := controllerruntime.Request{
			NamespacedName: types.NamespacedName{
				Name: currentCPE.GetName(),
			},
		}

		_, err := reconciler.Reconcile(context.TODO(), req)
		assert.Nil(t, err)

		// Non-local pod identifiers are tracked so a pod of the same replicaset
		// landing on this node later gets policies applied at launch
		val, ok := reconciler.podIdentifierToClusterPolicyEndpointMap.Load("deployment1rs@my-namespace")
		assert.True(t, ok)
		assert.True(t, lo.Contains(val.([]string), "allow-all-cnp-abcd"))
		val, ok = reconciler.clusterNetworkPolicyToPodIdentifierMap.Load("allow-all-cnp")
		assert.True(t, ok)
		assert.True(t, lo.Contains(val.([]string), "deployment1rs@my-namespace"))

		// Rollout on the remote node: old replicaset replaced by a new one
		currentCPE = getClusterPolicyEndpoint("allow-all-cnp", []policyendpoint.PodEndpoint{remotePod2})
		_, err = reconciler.Reconcile(context.TODO(), req)
		assert.Nil(t, err)

		_, ok = reconciler.podIdentifierToClusterPolicyEndpointMap.Load("deployment1rs@my-namespace")
		assert.False(t, ok)
		_, ok = reconciler.podIdentifierToClusterPolicyEndpointMap.Load("deployment2rs@my-namespace")
		assert.True(t, ok)

		cpeDeleted = true
		_, err = reconciler.Reconcile(context.TODO(), req)
		assert.Nil(t, err)
		assert.Equal(t, 0, sizeOfSyncMap(&reconciler.clusterNetworkPolicyToPodIdentifierMap))
		assert.Equal(t, 0, sizeOfSyncMap(&reconciler.podIdentifierToClusterPolicyEndpointMap))
		assert.Equal(t, 0, sizeOfSyncMap(&reconciler.ClusterPolicyEndpointSelectorMap))
	})
}

func getClusterPolicyEndpoint(cnpName string, podEndpoints []policyendpoint.PodEndpoint) policyendpoint.ClusterPolicyEndpoint {
	return policyendpoint.ClusterPolicyEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name: cnpName + "-abcd",
		},
		Spec: policyendpoint.ClusterPolicyEndpointSpec{
			PolicyRef: policyendpoint.ClusterPolicyReference{
				Name: cnpName,
			},
			Tier:                 policyendpoint.AdminTier,
			Priority:             1,
			PodSelectorEndpoints: podEndpoints,
		},
	}
}
