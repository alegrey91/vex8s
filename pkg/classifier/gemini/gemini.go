// Package gemini implements the Classifier interface using Google's Gemini
// API via the official google.golang.org/genai SDK. It asks the LLM to classify
// a CVE description into one or more of the canonical exploitation classes
// defined in pkg/class.
package gemini

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"google.golang.org/genai"

	"github.com/alegrey91/vex8s/pkg/class"
	"github.com/alegrey91/vex8s/pkg/classifier"
	"github.com/alegrey91/vex8s/pkg/mitigation"
)

const (
	// apiKeyEnv is the environment variable holding the Gemini API key.
	apiKeyEnv = "GEMINI_API_KEY"
	// modelEnv optionally overrides the model id.
	modelEnv = "GEMINI_MODEL"
	// defaultModel is used when GEMINI_MODEL is unset.
	defaultModel = "gemini-3.7-flash"
)

// Classifier calls the Gemini API to classify CVE descriptions.
type Classifier struct {
	client   *genai.Client
	model    string
	showLogs bool
}

// Validate checks that the required configuration is present without building
// the client or making any network call. It lets the CLI fail fast (in
// PreRunE) before any work is done when GEMINI_API_KEY is missing.
func Validate() error {
	if strings.TrimSpace(os.Getenv(apiKeyEnv)) == "" {
		return fmt.Errorf("the %s environment variable must be set to use the gemini classifier", apiKeyEnv)
	}
	return nil
}

// New constructs the Gemini classifier. It fails fast if the required
// GEMINI_API_KEY is not present, so misconfiguration surfaces before any CVE is
// processed rather than mid-run. When showLogs is true, per-CVE classification
// progress is written to stderr.
func New(showLogs bool) (*Classifier, error) {
	if err := Validate(); err != nil {
		return nil, err
	}
	model := strings.TrimSpace(os.Getenv(modelEnv))
	if model == "" {
		model = defaultModel
	}

	client, err := genai.NewClient(context.Background(), &genai.ClientConfig{
		APIKey:  strings.TrimSpace(os.Getenv(apiKeyEnv)),
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		return nil, fmt.Errorf("gemini: creating client: %w", err)
	}

	return &Classifier{client: client, model: model, showLogs: showLogs}, nil
}

// Classify sends the CVE description to Gemini and maps the structured response
// back to exploitation classes. The model is constrained via a response schema
// to return a JSON object with a "classes" array of canonical class identifiers.
func (c *Classifier) Classify(ctx context.Context, cve mitigation.CVE) (classifier.Prediction, error) {
	if c.showLogs {
		fmt.Fprintf(os.Stderr, "[*] classifier(gemini:%s): calling API for %s\n", c.model, cve.ID)
	}

	resp, err := c.client.Models.GenerateContent(
		ctx,
		c.model,
		genai.Text(classifier.BuildPrompt(cve)),
		responseConfig(),
	)
	if err != nil {
		return classifier.Prediction{}, fmt.Errorf("gemini: calling API: %w", err)
	}

	raw := strings.TrimSpace(resp.Text())
	if raw == "" {
		return classifier.Prediction{}, fmt.Errorf("gemini: empty response from API")
	}

	var result classificationResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return classifier.Prediction{}, fmt.Errorf("gemini: parsing classification %q: %w", raw, err)
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
		fmt.Fprintf(os.Stderr, "[+] classifier(gemini:%s): %s classified as %v\n", c.model, cve.ID, classes)
	}

	return classifier.Prediction{
		Classes: classes,
		Engine:  "gemini:" + c.model,
	}, nil
}

// Close releases resources. The SDK client needs no explicit teardown.
func (c *Classifier) Close() error {
	return nil
}

// classificationResult is the JSON shape Gemini is constrained to return.
type classificationResult struct {
	Classes []string `json:"classes"`
}

// responseConfig constrains the model to deterministic, structured JSON output:
// an object with a "classes" array whose values are the canonical exploitation
// classes.
func responseConfig() *genai.GenerateContentConfig {
	enum := make([]string, 0, len(class.All))
	for _, c := range class.All {
		enum = append(enum, string(c))
	}
	temp := float32(0)

	return &genai.GenerateContentConfig{
		Temperature:      &temp,
		ResponseMIMEType: "application/json",
		ResponseSchema: &genai.Schema{
			Type: genai.TypeObject,
			Properties: map[string]*genai.Schema{
				"classes": {
					Type:  genai.TypeArray,
					Items: &genai.Schema{Type: genai.TypeString, Enum: enum},
				},
			},
			Required:         []string{"classes"},
			PropertyOrdering: []string{"classes"},
		},
	}
}
