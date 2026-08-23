// Package embedded implements the Classifier interface using the ONNX ML model
// embedded in pkg/inference.
package embedded

import (
	"context"
	"fmt"
	"os"

	"github.com/alegrey91/vex8s/pkg/class"
	"github.com/alegrey91/vex8s/pkg/classifier"
	"github.com/alegrey91/vex8s/pkg/inference"
	"github.com/alegrey91/vex8s/pkg/mitigation"
)

// Classifier wraps the embedded ONNX model. The model is set up once and reused
// for the lifetime of the run.
type Classifier struct {
	model    *inference.Model
	showLogs bool
}

// New sets up the embedded model. Callers must Close it when done. When showLogs
// is true, per-CVE classification progress is written to stderr.
func New(showLogs bool) (*Classifier, error) {
	m := inference.NewModel()
	if err := m.Setup(); err != nil {
		return nil, fmt.Errorf("setting up embedded model: %w", err)
	}
	return &Classifier{model: m, showLogs: showLogs}, nil
}

// Classify runs the ONNX model over the CVE description. The model emits hard
// labels (no scores), so Confidence is left nil and Abstained is false.
func (c *Classifier) Classify(_ context.Context, cve mitigation.CVE) (classifier.Prediction, error) {
	if c.showLogs {
		fmt.Fprintf(os.Stderr, "[*] classifier(embedded-ml:%s): predicting for %s\n", c.model.Version, cve.ID)
	}

	labels, err := c.model.Predict(cve.Description)
	if err != nil {
		return classifier.Prediction{}, fmt.Errorf("embedded prediction: %w", err)
	}

	classes := make([]class.ExploitClass, 0, len(labels))
	for _, l := range labels {
		ec := class.ExploitClass(l)
		if ec.IsValid() {
			classes = append(classes, ec)
		}
	}

	if c.showLogs {
		fmt.Fprintf(os.Stderr, "[+] classifier(embedded-ml:%s): %s classified as %v\n", c.model.Version, cve.ID, classes)
	}

	return classifier.Prediction{
		Classes: classes,
		Engine:  "embedded-ml:" + c.model.Version,
	}, nil
}

// Close destroys the underlying model.
func (c *Classifier) Close() error {
	c.model.Destroy()
	return nil
}
