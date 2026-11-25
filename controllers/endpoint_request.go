package controllers

import (
	"context"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// EndpointRequest asks to reconcile one policy endpoint slice under one parent policy. NPC names
// slices with a truncated GenerateName, so long policy names can share a slice name. When a name
// moves to another parent, the old and new parent each get their own request and retries.
type EndpointRequest struct {
	Endpoint types.NamespacedName
	Parent   string
}

// endpointEventHandler enqueues a slice under the parent each event carries. An update that
// changes the parent, such as a delete and recreate folded together by a relist, enqueues both.
func endpointEventHandler[T client.Object](parentOf func(T) string) handler.TypedEventHandler[T, EndpointRequest] {
	enqueue := func(q workqueue.TypedRateLimitingInterface[EndpointRequest], obj T) {
		q.Add(EndpointRequest{Endpoint: client.ObjectKeyFromObject(obj), Parent: parentOf(obj)})
	}
	return handler.TypedFuncs[T, EndpointRequest]{
		CreateFunc: func(_ context.Context, e event.TypedCreateEvent[T], q workqueue.TypedRateLimitingInterface[EndpointRequest]) {
			enqueue(q, e.Object)
		},
		UpdateFunc: func(_ context.Context, e event.TypedUpdateEvent[T], q workqueue.TypedRateLimitingInterface[EndpointRequest]) {
			enqueue(q, e.ObjectOld)
			enqueue(q, e.ObjectNew)
		},
		DeleteFunc: func(_ context.Context, e event.TypedDeleteEvent[T], q workqueue.TypedRateLimitingInterface[EndpointRequest]) {
			enqueue(q, e.Object)
		},
		GenericFunc: func(_ context.Context, e event.TypedGenericEvent[T], q workqueue.TypedRateLimitingInterface[EndpointRequest]) {
			enqueue(q, e.Object)
		},
	}
}

func setupEndpointController[T client.Object](mgr ctrl.Manager, name string, obj T, parentOf func(T) string,
	r reconcile.TypedReconciler[EndpointRequest], options controller.TypedOptions[EndpointRequest]) error {
	return builder.TypedControllerManagedBy[EndpointRequest](mgr).
		Named(name).
		WithOptions(options).
		WatchesRawSource(source.TypedKind(mgr.GetCache(), obj, endpointEventHandler(parentOf))).
		Complete(r)
}
