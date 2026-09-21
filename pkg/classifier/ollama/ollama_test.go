package ollama

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alegrey91/vex8s/pkg/class"
	"github.com/alegrey91/vex8s/pkg/mitigation"
)

// stubServer spins up an httptest server that answers /api/version (for
// Validate) and /api/generate (returning the supplied response body), then
// points the classifier at it via OLLAMA_HOST.
func stubServer(t *testing.T, generate func(w http.ResponseWriter, r *http.Request)) *Classifier {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"version":"0.0.0-test"}`)
	})
	mux.HandleFunc("/api/generate", generate)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	t.Setenv(hostEnv, srv.URL)
	t.Setenv(modelEnv, "test-model")

	c, err := New(false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// generateWith returns a handler that replies with the given model text as the
// "response" field of an Ollama /api/generate reply.
func generateWith(modelText string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(generateResponse{Response: modelText})
	}
}

func TestClassifyHappyPath(t *testing.T) {
	c := stubServer(t, generateWith(`{"classes":["arbitrary_file_write","resource_exhaustion"]}`))

	pred, err := c.Classify(context.Background(), mitigation.CVE{ID: "CVE-2023-0001"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	want := []class.ExploitClass{class.ArbitraryFileWrite, class.ResourceExhaustion}
	if len(pred.Classes) != len(want) {
		t.Fatalf("got %v, want %v", pred.Classes, want)
	}
	for i := range want {
		if pred.Classes[i] != want[i] {
			t.Fatalf("got %v, want %v", pred.Classes, want)
		}
	}
	if pred.Engine != "ollama:test-model" {
		t.Fatalf("Engine = %q, want ollama:test-model", pred.Engine)
	}
}

func TestClassifyFiltersInvalidAndDedupes(t *testing.T) {
	c := stubServer(t, generateWith(`{"classes":["arbitrary_file_read","bogus_class","arbitrary_file_read"]}`))

	pred, err := c.Classify(context.Background(), mitigation.CVE{ID: "CVE-2023-0002"})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if len(pred.Classes) != 1 || pred.Classes[0] != class.ArbitraryFileRead {
		t.Fatalf("got %v, want [arbitrary_file_read]", pred.Classes)
	}
}

func TestClassifyEmptyResponse(t *testing.T) {
	c := stubServer(t, generateWith("   "))
	if _, err := c.Classify(context.Background(), mitigation.CVE{ID: "CVE-2023-0003"}); err == nil {
		t.Fatal("expected error on empty response, got nil")
	}
}

func TestClassifyMalformedJSON(t *testing.T) {
	c := stubServer(t, generateWith(`{"classes": not-json`))
	if _, err := c.Classify(context.Background(), mitigation.CVE{ID: "CVE-2023-0004"}); err == nil {
		t.Fatal("expected error on malformed JSON, got nil")
	}
}

func TestClassifyServerError(t *testing.T) {
	c := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	if _, err := c.Classify(context.Background(), mitigation.CVE{ID: "CVE-2023-0005"}); err == nil {
		t.Fatal("expected error on 500 status, got nil")
	}
}

func TestValidateServerUnreachable(t *testing.T) {
	// Unused port; nothing listening.
	t.Setenv(hostEnv, "http://127.0.0.1:1")
	if err := Validate(); err == nil {
		t.Fatal("expected error when server unreachable, got nil")
	}
}

func TestValidateReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"version":"0.0.0-test"}`)
	}))
	t.Cleanup(srv.Close)
	t.Setenv(hostEnv, srv.URL)
	if err := Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestDefaultsWhenEnvUnset(t *testing.T) {
	t.Setenv(hostEnv, "")
	t.Setenv(modelEnv, "")
	if got := host(); got != defaultHost {
		t.Fatalf("host() = %q, want %q", got, defaultHost)
	}
	if got := model(); got != defaultModel {
		t.Fatalf("model() = %q, want %q", got, defaultModel)
	}
}

func TestRequestShape(t *testing.T) {
	var captured generateRequest
	c := stubServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Errorf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(generateResponse{Response: `{"classes":[]}`})
	})

	if _, err := c.Classify(context.Background(), mitigation.CVE{ID: "CVE-2023-0006", Description: "x"}); err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if captured.Model != "test-model" {
		t.Errorf("Model = %q, want test-model", captured.Model)
	}
	if captured.Stream {
		t.Error("Stream = true, want false")
	}
	if captured.Options.Temperature != 0 {
		t.Errorf("Temperature = %v, want 0", captured.Options.Temperature)
	}
	if len(captured.Format) == 0 {
		t.Error("Format schema is empty")
	}
}
