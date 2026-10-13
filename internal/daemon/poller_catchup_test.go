package daemon

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/TrueOpen/cortex/internal/chainclient"
)

// A node that fell far behind the tip used to read the whole backlog as one
// page before it committed anything, and readiness said "Keeper event lag is
// not known yet" for as long as that took -- more than ten hours on the
// testnet after a day of downtime. Against the real Comet client the poller
// now commits one bounded page per pass and reports the lag each time, so
// readiness sees the node catching up and a failure costs one page, not all.
func TestKeeperPollerCatchesUpOneBoundedPageAtATime(t *testing.T) {
	ctx := context.Background()
	const tip = 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		height := r.URL.Query().Get("height")
		switch r.URL.Path {
		case "/status":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"node_info":{"network":"trueopen-devnet-1"},"sync_info":{"latest_block_height":"%d"}}}`, tip)
		case "/block_results":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"height":%q,"txs_results":[],"finalize_block_events":[]}}`, height)
		case "/block":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"block":{"header":{"chain_id":"trueopen-devnet-1","height":%q},"data":{"txs":[]}}}}`, height)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	events := chainclient.NewCometEventClient(chainclient.CometEventClientConfig{RPCURL: server.URL, ChainID: "trueopen-devnet-1", MaxBlocksPerPage: 200})
	db := openPollerTestStore(t)
	var progress []ChainProgress
	poller := NewKeeperPoller(db, events, NewReconciler(ReconcilerOptions{}), KeeperPollerConfig{
		ObserveChainProgress: func(p ChainProgress) { progress = append(progress, p) },
	})

	var cursors []uint64
	for i := range 3 {
		if err := poller.RunOnce(ctx); err != nil {
			t.Fatalf("pass %d: %v", i+1, err)
		}
		height, err := db.KeeperLastProcessedHeight(ctx)
		if err != nil {
			t.Fatal(err)
		}
		cursors = append(cursors, height)
	}
	if want := []uint64{200, 400, 500}; !reflect.DeepEqual(cursors, want) {
		t.Fatalf("cursor after each pass = %v, want %v", cursors, want)
	}
	// The first pass reports progress before it has committed anything, so
	// readiness knows the lag from the first page on.
	if len(progress) == 0 || progress[0].ChainHeight != tip {
		t.Fatalf("progress = %+v, want the tip reported on the first pass", progress)
	}
	if last := progress[len(progress)-1]; last.Lag() != 0 {
		t.Fatalf("last progress = %+v, want caught up", last)
	}
}
