package modelservice

import "context"

type inferStreamObserverKey struct{}

// WithInferStreamObserver scopes an observer to one inference request. Concurrent
// tasks sharing LocalService must not replace each other's process-wide sink.
func WithInferStreamObserver(ctx context.Context, observer InferStreamObserver) context.Context {
	return context.WithValue(ctx, inferStreamObserverKey{}, observer)
}

func (s *LocalService) observerForRequest(ctx context.Context) InferStreamObserver {
	if observer, ok := ctx.Value(inferStreamObserverKey{}).(InferStreamObserver); ok {
		return observer
	}
	return s.inferObserver()
}
