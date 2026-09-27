package modelservice

import (
	"fmt"
	"testing"
	"time"
)

// newBoundLocalService is NewLocalService with testQwenModelID bound to its
// served repository, as the daemon binds a configured model at startup.
func newBoundLocalService(baseURL, serviceID string, maxConcurrency uint32, inferTimeout, probeTimeout time.Duration) *LocalService {
	svc := NewLocalService(baseURL, serviceID, maxConcurrency, inferTimeout, probeTimeout)
	if err := svc.BindModel(testQwenModelID(), LocalModelProvider, "Qwen/Qwen3-8B"); err != nil {
		panic(err)
	}
	return svc
}

func TestBindModelRefusesANonLocalProvider(t *testing.T) {
	svc := NewLocalService("http://127.0.0.1:1", "", 1, time.Second, time.Second)
	if err := svc.BindModel(testQwenModelID(), "OCI", "Qwen/Qwen3-8B"); err == nil {
		t.Fatal("BindModel accepted an OCI-sourced model on the vLLM adapter")
	}
	if err := svc.BindModel(testQwenModelID(), LocalModelProvider, "Qwen/Qwen3-8B"); err != nil {
		t.Fatalf("BindModel with the local provider: %v", err)
	}
}

// fullTopRow pads lead to a defaultTopK-entry top_logprobs row with distinct
// filler ids whose logprobs keep falling, the shape vLLM returns.
func fullTopRow(lead ...TopLogprob) TopLogprobRow {
	return topRowOf(defaultTopK, lead...)
}

// topRowOf is fullTopRow for a k-entry row.
func topRowOf(k int, lead ...TopLogprob) TopLogprobRow {
	row := append(TopLogprobRow(nil), lead...)
	last := row[len(row)-1].Logprob
	for id := 900000; len(row) < k; id++ {
		last--
		row = append(row, TopLogprob{Token: fmt.Sprintf("token_id:%d", id), Logprob: last})
	}
	return row
}

// withFullTopK gives every generated position of a completions fixture a
// full top_logprobs row led by the generated token, as vLLM does, so fixtures
// that do not care about top-k stay terse.
func withFullTopK(resp completionResponse) completionResponse {
	return withTopK(resp, defaultTopK)
}

// withTopK is withFullTopK for k-entry rows.
func withTopK(resp completionResponse, k int) completionResponse {
	for c := range resp.Choices {
		lp := resp.Choices[c].Logprobs
		if lp == nil {
			continue
		}
		rows := append([]TopLogprobRow(nil), lp.TopLogprobs...)
		for i, id := range resp.Choices[c].TokenIDs {
			if i >= len(lp.TokenLogprobs) {
				break
			}
			if i >= len(rows) {
				rows = append(rows, nil)
			}
			if len(rows[i]) == 0 {
				rows[i] = topRowOf(k, TopLogprob{Token: fmt.Sprintf("token_id:%d", id), Logprob: lp.TokenLogprobs[i]})
			}
		}
		clone := *lp
		clone.TopLogprobs = rows
		resp.Choices[c].Logprobs = &clone
	}
	return resp
}

// chatFullTopK pads each chat logprobs entry's top_logprobs to a full row.
func chatFullTopK(lp *chatRespLogprobs) *chatRespLogprobs {
	if lp == nil {
		return nil
	}
	clone := chatRespLogprobs{Content: append([]chatRespLogprobContent(nil), lp.Content...)}
	for i, entry := range clone.Content {
		lead := chatTopLogprobRow(entry.TopLogprobs)
		if len(lead) == 0 {
			lead = TopLogprobRow{{Token: entry.Token, Logprob: entry.Logprob}}
		}
		row := fullTopRow(lead...)
		top := make([]chatRespTopLogprob, len(row))
		for j, t := range row {
			top[j] = chatRespTopLogprob{Token: t.Token, Logprob: t.Logprob}
		}
		clone.Content[i].TopLogprobs = top
	}
	return &clone
}
