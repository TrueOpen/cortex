package modelservice

import "testing"

func TestResourceSnapshotAvailableSlots(t *testing.T) {
	for _, test := range []struct {
		name     string
		snapshot ResourceSnapshot
		want     int
		wantErr  bool
	}{
		{name: "available", snapshot: ResourceSnapshot{QueueDepth: 2, MaxConcurrency: 5}, want: 3},
		{name: "exhausted", snapshot: ResourceSnapshot{QueueDepth: 5, MaxConcurrency: 5}, want: 0},
		{name: "missing max", snapshot: ResourceSnapshot{}, wantErr: true},
		{name: "over capacity", snapshot: ResourceSnapshot{QueueDepth: 6, MaxConcurrency: 5}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.snapshot.AvailableSlots()
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("AvailableSlots() = %d, %v, want %d error=%v", got, err, test.want, test.wantErr)
			}
		})
	}
}
