package daemon

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SingaXYZ/cortex/internal/builderclient"
	"github.com/SingaXYZ/cortex/internal/diagnostics"
)

func TestReadinessControllerStartsStopsAndRestartsWorkloadOnTransitions(t *testing.T) {
	var mu sync.Mutex
	state := workloadReadiness(false)
	starts := 0
	stops := 0
	deactivations := 0
	started := make(chan int, 3)
	stopped := make(chan int, 3)
	deactivated := make(chan int, 3)

	controller := NewReadinessController(ReadinessControllerConfig{
		Interval: time.Millisecond,
		Check: func(context.Context) WorkloadReadiness {
			mu.Lock()
			defer mu.Unlock()
			return state
		},
		Start: func(ctx context.Context, readiness WorkloadReadiness, markStarted func()) error {
			if readiness.ServiceAddress != "trueopen1service" {
				t.Errorf("Start service address = %q", readiness.ServiceAddress)
			}
			mu.Lock()
			starts++
			count := starts
			mu.Unlock()
			started <- count
			markStarted()
			<-ctx.Done()
			mu.Lock()
			stops++
			count = stops
			mu.Unlock()
			stopped <- count
			return nil
		},
		Stop: func() {
			mu.Lock()
			deactivations++
			count := deactivations
			mu.Unlock()
			deactivated <- count
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()

	setReadinessState(&mu, &state, workloadReadiness(true))
	waitForControllerCount(t, started, 1)
	time.Sleep(10 * time.Millisecond)
	assertControllerCount(t, &mu, &starts, 1, "starts")

	setReadinessState(&mu, &state, workloadReadiness(false))
	waitForControllerCount(t, stopped, 1)
	waitForControllerCount(t, deactivated, 1)
	setReadinessState(&mu, &state, workloadReadiness(true))
	waitForControllerCount(t, started, 2)

	cancel()
	waitForControllerCount(t, stopped, 2)
	waitForControllerCount(t, deactivated, 2)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadinessController did not stop")
	}
}

func TestReadinessControllerSurfacesForeignWorkloadDeadline(t *testing.T) {
	controller := NewReadinessController(ReadinessControllerConfig{
		Interval: time.Hour,
		Check: func(context.Context) WorkloadReadiness {
			return workloadReadiness(true)
		},
		Start: func(context.Context, WorkloadReadiness, func()) error {
			return fmt.Errorf("keeper timeout: %w", context.DeadlineExceeded)
		},
	})

	err := controller.Run(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run() error = %v, want foreign deadline", err)
	}
}

func TestReadinessControllerRestartsWorkloadWhenCurrentServiceAddressChanges(t *testing.T) {
	var mu sync.Mutex
	state := workloadReadiness(true)
	started := make(chan string, 2)
	stopped := make(chan struct{}, 2)

	controller := NewReadinessController(ReadinessControllerConfig{
		Interval: time.Millisecond,
		Check: func(context.Context) WorkloadReadiness {
			mu.Lock()
			defer mu.Unlock()
			return state
		},
		Start: func(ctx context.Context, readiness WorkloadReadiness, markStarted func()) error {
			started <- readiness.ServiceAddress
			markStarted()
			<-ctx.Done()
			stopped <- struct{}{}
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()
	if got := <-started; got != "trueopen1service" {
		t.Fatalf("initial service = %q", got)
	}

	mu.Lock()
	state.ServiceAddress = "trueopen1service2"
	mu.Unlock()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("old service workload was not stopped")
	}
	select {
	case got := <-started:
		if got != "trueopen1service2" {
			t.Fatalf("rotated service = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("new service workload was not started")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadinessController did not stop")
	}
}

func workloadReadiness(ready bool) WorkloadReadiness {
	return WorkloadReadiness{
		ServiceAddress:    "trueopen1service",
		Identity:          diagnostics.DependencyStatus{Name: "keeper_identity", Ready: ready},
		ModelSupport:      diagnostics.DependencyStatus{Name: "model_support", Ready: ready},
		ChainSync:         diagnostics.DependencyStatus{Name: "chain_sync", Ready: ready},
		DependenciesReady: ready,
	}
}

func setReadinessState(mu *sync.Mutex, state *WorkloadReadiness, value WorkloadReadiness) {
	mu.Lock()
	defer mu.Unlock()
	*state = value
}

func waitForControllerCount(t *testing.T, ch <-chan int, want int) {
	t.Helper()
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("controller count = %d, want %d", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("controller did not reach count %d", want)
	}
}

func assertControllerCount(t *testing.T, mu *sync.Mutex, got *int, want int, name string) {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	if *got != want {
		t.Fatalf("%s = %d, want %d", name, *got, want)
	}
}

// The controller owns the workload lifecycle, so it is the only place that
// knows whether the runners are live. Readiness reads that through
// ObserveWorkload; without it a node whose workload has exited keeps answering
// /readyz with 200 because every boundary it depended on is still reachable.
func TestReadinessControllerReportsWorkloadLifecycle(t *testing.T) {
	var mu sync.Mutex
	state := workloadReadiness(false)
	var observed []bool
	transitions := make(chan bool, 8)
	started := make(chan int, 4)
	starts := 0

	controller := NewReadinessController(ReadinessControllerConfig{
		Interval: time.Millisecond,
		Check: func(context.Context) WorkloadReadiness {
			mu.Lock()
			defer mu.Unlock()
			return state
		},
		ObserveWorkload: func(running bool) {
			mu.Lock()
			observed = append(observed, running)
			mu.Unlock()
			transitions <- running
		},
		Start: func(ctx context.Context, _ WorkloadReadiness, markStarted func()) error {
			mu.Lock()
			starts++
			count := starts
			mu.Unlock()
			started <- count
			markStarted()
			<-ctx.Done()
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()

	// Before anything is ready the workload must not be reported as running.
	waitForWorkloadReport(t, transitions, false)

	setReadinessState(&mu, &state, workloadReadiness(true))
	waitForControllerCount(t, started, 1)
	waitForWorkloadReport(t, transitions, true)

	// Losing readiness must be reported, not just acted on.
	setReadinessState(&mu, &state, workloadReadiness(false))
	waitForWorkloadReport(t, transitions, false)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadinessController did not stop")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(observed) < 3 || observed[0] || !observed[1] || observed[2] {
		t.Fatalf("workload reports = %v, want false then true then false", observed)
	}
}

func TestReadinessControllerWaitsForWorkloadStartupSignal(t *testing.T) {
	transitions := make(chan bool, 8)
	startEntered := make(chan struct{})
	releaseStartup := make(chan struct{})
	controller := NewReadinessController(ReadinessControllerConfig{
		Interval: time.Millisecond,
		Check: func(context.Context) WorkloadReadiness {
			return workloadReadiness(true)
		},
		ObserveWorkload: func(running bool) { transitions <- running },
		Start: func(ctx context.Context, _ WorkloadReadiness, markStarted func()) error {
			close(startEntered)
			<-releaseStartup
			markStarted()
			<-ctx.Done()
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()
	waitForWorkloadReport(t, transitions, false)
	select {
	case <-startEntered:
	case <-time.After(time.Second):
		t.Fatal("workload Start was not called")
	}
	select {
	case got := <-transitions:
		t.Fatalf("workload was reported as %v before startup completed", got)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseStartup)
	waitForWorkloadReport(t, transitions, true)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadinessController did not stop")
	}
}

func waitForWorkloadReport(t *testing.T, reports <-chan bool, want bool) {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		select {
		case got := <-reports:
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("no workload report of %v", want)
		}
	}
}

// The workload can exit on its own while every dependency stays ready — a
// JetStream durable already bound elsewhere does exactly this. That is the case
// where stale readiness is most misleading, because nothing else changes.
func TestReadinessControllerReportsWorkloadThatExitsOnItsOwn(t *testing.T) {
	var mu sync.Mutex
	state := workloadReadiness(true)
	transitions := make(chan bool, 8)
	release := make(chan struct{})
	var releaseOnce sync.Once

	controller := NewReadinessController(ReadinessControllerConfig{
		Interval: time.Millisecond,
		Check: func(context.Context) WorkloadReadiness {
			mu.Lock()
			defer mu.Unlock()
			return state
		},
		ObserveWorkload: func(running bool) { transitions <- running },
		Start: func(_ context.Context, _ WorkloadReadiness, markStarted func()) error {
			markStarted()
			<-release
			// A clean exit with readiness unchanged: the controller keeps
			// running, so only the workload report can reveal the gap.
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()

	waitForWorkloadReport(t, transitions, false)
	waitForWorkloadReport(t, transitions, true)

	// Let the workload return by itself.
	releaseOnce.Do(func() { close(release) })
	waitForWorkloadReport(t, transitions, false)

	// Readiness never dropped, so the controller keeps restarting the workload.
	// Drain the reports so it is not blocked on the channel during shutdown.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range transitions {
		}
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ReadinessController did not stop")
	}
	close(transitions)
	<-drained
}

func TestReadinessControllerRetriesRetryableWorkloadFailure(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	const retryInterval = 80 * time.Millisecond
	reported := make(chan error, 4)
	attemptedAt := make(chan time.Time, 2)

	controller := NewReadinessController(ReadinessControllerConfig{
		Interval: retryInterval,
		Check: func(context.Context) WorkloadReadiness {
			return workloadReadiness(true)
		},
		OnRetryableFailure: func(err error) { reported <- err },
		Start: func(ctx context.Context, _ WorkloadReadiness, markStarted func()) error {
			attemptedAt <- time.Now()
			mu.Lock()
			attempts++
			attempt := attempts
			mu.Unlock()
			if attempt == 1 {
				// The subscribe failed, so startup never completes: the
				// workload must not be reported as running for this attempt.
				return builderclient.Retryable(errors.New(`nats subscribe "trueopen.worker-assignment.*": consumer is already bound to a subscription`))
			}
			markStarted()
			<-ctx.Done()
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()
	firstAttempt := <-attemptedAt

	select {
	case err := <-reported:
		if !strings.Contains(err.Error(), "already bound") {
			t.Fatalf("reported error = %v, want the durable binding conflict", err)
		}
	case <-time.After(time.Second):
		t.Fatal("retryable workload failure was not reported")
	}
	select {
	case secondAttempt := <-attemptedAt:
		if elapsed := secondAttempt.Sub(firstAttempt); elapsed < retryInterval-10*time.Millisecond {
			t.Fatalf("workload retried after %s, want at least one %s readiness interval", elapsed, retryInterval)
		}
	case <-time.After(time.Second):
		t.Fatal("controller did not retry the workload after a retryable failure")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v, want a retryable failure not to stop the daemon", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadinessController did not stop")
	}
}

// A non-retryable workload failure must still be fatal.
func TestReadinessControllerStopsOnNonRetryableWorkloadFailure(t *testing.T) {
	want := errors.New("task input resolver is not available")
	controller := NewReadinessController(ReadinessControllerConfig{
		Interval: time.Millisecond,
		Check:    func(context.Context) WorkloadReadiness { return workloadReadiness(true) },
		Start:    func(context.Context, WorkloadReadiness, func()) error { return want },
	})
	if err := controller.Run(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Run() error = %v, want %v", err, want)
	}
}

// The three readiness concerns interact, and each was developed separately:
// chain_sync gates activation while a node replays its backlog, the workload
// report distinguishes a serving node from one whose boundaries are merely
// reachable, and a retryable start failure must neither stop the daemon nor be
// reported as serving. This covers them together, because a resolution that
// keeps only some of them still compiles.
func TestReadinessControllerCombinesChainSyncWorkloadAndRetry(t *testing.T) {
	var mu sync.Mutex
	catchingUp := true
	attempts := 0
	const interval = 40 * time.Millisecond
	transitions := make(chan bool, 16)
	attempted := make(chan struct{}, 4)
	retryable := make(chan error, 4)

	controller := NewReadinessController(ReadinessControllerConfig{
		Interval: interval,
		Check: func(context.Context) WorkloadReadiness {
			mu.Lock()
			defer mu.Unlock()
			readiness := workloadReadiness(true)
			if catchingUp {
				readiness.ChainSync = diagnostics.DependencyStatus{
					Name: "chain_sync", Ready: false,
					Error: "Keeper event lag 304 exceeds max 20; catching up",
				}
			}
			return readiness
		},
		ObserveWorkload:    func(running bool) { transitions <- running },
		OnRetryableFailure: func(err error) { retryable <- err },
		Start: func(ctx context.Context, _ WorkloadReadiness, markStarted func()) error {
			attempted <- struct{}{}
			mu.Lock()
			attempts++
			attempt := attempts
			mu.Unlock()
			if attempt == 1 {
				return builderclient.Retryable(errors.New(`nats subscribe "trueopen.worker-assignment.*": consumer is already bound to a subscription`))
			}
			markStarted()
			<-ctx.Done()
			return nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()

	// 1. Behind the chain tip: no workload may start at all.
	waitForWorkloadReport(t, transitions, false)
	select {
	case <-attempted:
		t.Fatal("workload started while the node was still catching up")
	case <-time.After(3 * interval):
	}

	// 2. Caught up: the first attempt hits a bound durable. It must be reported
	// as retryable, must not stop the controller, and must not be reported as
	// serving.
	mu.Lock()
	catchingUp = false
	mu.Unlock()
	select {
	case err := <-retryable:
		if !strings.Contains(err.Error(), "already bound") {
			t.Fatalf("retryable error = %v, want the durable binding conflict", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retryable workload failure was not reported")
	}

	// 3. The retry succeeds and only then is the node reported as serving.
	waitForWorkloadReport(t, transitions, true)

	mu.Lock()
	got := attempts
	mu.Unlock()
	if got < 2 {
		t.Fatalf("workload attempts = %d, want the failed start to have been retried", got)
	}

	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range transitions {
		}
	}()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadinessController did not stop")
	}
	close(transitions)
	<-drained
}

// DependencyStatuses is what the health endpoint and the readiness log both
// walk. A boundary added to WorkloadReadiness and left out of that list would
// silently stop being reported, so the list is checked against the struct
// itself rather than against a second hand-written list.
func TestWorkloadReadinessDependencyStatusesCoverEveryProbedBoundary(t *testing.T) {
	statusType := reflect.TypeOf(diagnostics.DependencyStatus{})
	value := reflect.ValueOf(WorkloadReadiness{})
	var fields []string
	for index := range value.NumField() {
		field := value.Type().Field(index)
		if field.Type == statusType {
			fields = append(fields, field.Name)
		}
	}
	if len(fields) == 0 {
		t.Fatal("WorkloadReadiness declares no dependency statuses")
	}

	// Each field is set to a status named after itself, so a duplicated or
	// missing field is visible rather than hidden behind identical zero values.
	readiness := WorkloadReadiness{}
	mutable := reflect.ValueOf(&readiness).Elem()
	for _, name := range fields {
		mutable.FieldByName(name).Set(reflect.ValueOf(diagnostics.DependencyStatus{Name: name}))
	}

	reported := readiness.DependencyStatuses()
	if len(reported) != len(fields) {
		t.Fatalf("DependencyStatuses() reported %d statuses, want %d: %v", len(reported), len(fields), reported)
	}
	seen := make(map[string]int, len(reported))
	for _, status := range reported {
		seen[status.Name]++
	}
	for _, name := range fields {
		if seen[name] != 1 {
			t.Fatalf("DependencyStatuses() reported field %s %d times, want exactly once", name, seen[name])
		}
	}
}
