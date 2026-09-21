// Package ollama implements the Classifier interface using a locally running
// Ollama server (https://ollama.com). It asks the LLM to classify a CVE
// description into one or more of the canonical exploitation classes defined in
// pkg/class. Unlike the gemini backend it needs no API key and runs entirely
// offline against the user's own machine.
package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alegrey91/vex8s/pkg/class"
	"github.com/alegrey91/vex8s/pkg/classifier"
	"github.com/alegrey91/vex8s/pkg/mitigation"
)

const (
	// hostEnv optionally overrides the Ollama server base URL.
	hostEnv = "OLLAMA_HOST"
	// modelEnv optionally overrides the model id.
	modelEnv = "OLLAMA_MODEL"
	// defaultHost is the Ollama server address used when OLLAMA_HOST is unset.
	defaultHost = "http://localhost:11434"
	// defaultModel is a small instruction-tuned model that runs on modest
	// hardware while following the structured-output contract reliably.
	defaultModel = "qwen2.5:3b-instruct"
)

// Classifier calls a local Ollama server to classify CVE descriptions.
type Classifier struct {
	client   *http.Client
	host     string
	model    string
	showLogs bool
}

// host resolves the Ollama base URL from the environment, trimming any trailing
// slash so paths can be joined uniformly.
func host() string {
	h := strings.TrimSpace(os.Getenv(hostEnv))
	if h == "" {
		h = defaultHost
	}
	return strings.TrimRight(h, "/")
}

// model resolves the model id from the environment.
func model() string {
	m := strings.TrimSpace(os.Getenv(modelEnv))
	if m == "" {
		m = defaultModel
	}
	return m
}

// Validate checks that the Ollama server is reachable without running a
// classification. It lets the CLI fail fast (in PreRunE) when the server is not
// running or OLLAMA_HOST points at the wrong address, rather than erroring
// mid-run on the first CVE.
func Validate() error {
	req, err := http.NewRequest(http.MethodGet, host()+"/api/version", nil)
	if err != nil {
		return fmt.Errorf("ollama: building version request: %w", err)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ollama: server not reachable at %s (is `ollama serve` running?): %w", host(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama: server at %s returned status %d", host(), resp.StatusCode)
	}
	return nil
}

// New constructs the Ollama classifier. It fails fast if the server is not
// reachable, so misconfiguration surfaces before any CVE is processed. When
// showLogs is true, per-CVE classification progress is written to stderr.
func New(showLogs bool) (*Classifier, error) {
	if err := Validate(); err != nil {
		return nil, err
	}
	return &Classifier{
		// No overall timeout: local model inference on constrained hardware can
		// take a while per request. Cancellation is driven by the request ctx.
		client:   &http.Client{},
		host:     host(),
		model:    model(),
		showLogs: showLogs,
	}, nil
}

// generateRequest is the payload sent to Ollama's /api/generate endpoint. The
// Format field carries a JSON schema so the model is constrained to structured
// output; Options.Temperature=0 makes the classification deterministic.
type generateRequest struct {
	Model   string          `json:"model"`
	Prompt  string          `json:"prompt"`
	Stream  bool            `json:"stream"`
	Format  json.RawMessage `json:"format"`
	Options generateOptions `json:"options"`
}

type generateOptions struct {
	Temperature float64 `json:"temperature"`
}

// generateResponse is the (non-streamed) reply from /api/generate. Response
// holds the model's text, which itself is the JSON document constrained by
// Format.
type generateResponse struct {
	Response string `json:"response"`
}

// classificationResult is the JSON shape the model is constrained to return.
type classificationResult struct {
	Classes []string `json:"classes"`
}

// Classify sends the CVE description to the Ollama server and maps the
// structured response back to exploitation classes. The model is constrained via
// a JSON schema to return an object with a "classes" array of canonical class
// identifiers.
func (c *Classifier) Classify(ctx context.Context, cve mitigation.CVE) (classifier.Prediction, error) {
	if c.showLogs {
		fmt.Fprintf(os.Stderr, "[*] classifier(ollama:%s): calling API for %s\n", c.model, cve.ID)
	}

	body, err := json.Marshal(generateRequest{
		Model:   c.model,
		Prompt:  classifier.BuildPrompt(cve),
		Stream:  false,
		Format:  responseSchema(),
		Options: generateOptions{Temperature: 0},
	})
	if err != nil {
		return classifier.Prediction{}, fmt.Errorf("ollama: encoding request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.host+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return classifier.Prediction{}, fmt.Errorf("ollama: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return classifier.Prediction{}, fmt.Errorf("ollama: calling API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return classifier.Prediction{}, fmt.Errorf("ollama: API returned status %d", resp.StatusCode)
	}

	var gen generateResponse
	if err := json.NewDecoder(resp.Body).Decode(&gen); err != nil {
		return classifier.Prediction{}, fmt.Errorf("ollama: decoding API response: %w", err)
	}

	raw := strings.TrimSpace(gen.Response)
	if raw == "" {
		return classifier.Prediction{}, fmt.Errorf("ollama: empty response from API")
	}

	var result classificationResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return classifier.Prediction{}, fmt.Errorf("ollama: parsing classification %q: %w", raw, err)
	}

	classes := make([]class.ExploitClass, 0, len(result.Classes))
	seen := map[class.ExploitClass]bool{}
	for _, l := range result.Classes {
		ec := class.ExploitClass(strings.TrimSpace(l))
		if ec.IsValid() && !seen[ec] {
			classes = append(classes, ec)
			seen[ec] = true
		}
	}

	if c.showLogs {
		fmt.Fprintf(os.Stderr, "[+] classifier(ollama:%s): %s classified as %v\n", c.model, cve.ID, classes)
	}

	return classifier.Prediction{
		Classes: classes,
		Engine:  "ollama:" + c.model,
	}, nil
}

// Close releases resources. The stdlib HTTP client needs no explicit teardown.
func (c *Classifier) Close() error {
	return nil
}

// responseSchema returns the JSON schema constraining the model to an object
// with a "classes" array whose values are the canonical exploitation classes.
// It mirrors the response schema used by the gemini backend so both LLM engines
// return the same shape.
func responseSchema() json.RawMessage {
	enum := make([]string, 0, len(class.All))
	for _, c := range class.All {
		enum = append(enum, string(c))
	}
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"classes": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type": "string",
					"enum": enum,
				},
			},
		},
		"required": []string{"classes"},
	}
	b, _ := json.Marshal(schema)
	return b
}
