package modelservice

import "time"

// newBoundLocalService is NewLocalService with testQwenModelID bound to its
// served repository, as the daemon binds a configured model at startup.
func newBoundLocalService(baseURL, serviceID string, maxConcurrency uint32, inferTimeout, probeTimeout time.Duration) *LocalService {
	svc := NewLocalService(baseURL, serviceID, maxConcurrency, inferTimeout, probeTimeout)
	if err := svc.BindModel(testQwenModelID(), "Qwen/Qwen3-8B"); err != nil {
		panic(err)
	}
	return svc
}
