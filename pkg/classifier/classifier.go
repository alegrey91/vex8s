// Package classifier defines the pluggable engine that predicts the
// exploitation class(es) of a CVE from its description. This is the "recall"
// signal in the decision chain. Backends implement the Classifier interface so
// the embedded ML model and future LLM backends (e.g. Anthropic) are
// interchangeable behind a single contract.
package classifier

import (
	"context"

	"github.com/alegrey91/vex8s/pkg/class"
	"github.com/alegrey91/vex8s/pkg/mitigation"
)

// Prediction is the uniform output contract every backend must satisfy.
type Prediction struct {
	// Classes are the predicted exploitation classes (may be empty).
	Classes []class.ExploitClass
	// Confidence is an optional per-class score in [0,1]. Backends that cannot
	// produce scores (e.g. the embedded ML model) may leave this nil or set
	// 1.0 for predicted classes.
	Confidence map[class.ExploitClass]float64
	// Abstained is true when the backend declined to classify (low confidence,
	// ambiguous description). An abstention must never lead to suppression.
	Abstained bool
	// Engine identifies the backend and version, e.g. "embedded-ml:v3" or
	// "anthropic:claude-...". Recorded in the VEX for auditability.
	Engine string
}

// Classifier predicts exploitation classes for a CVE. Implementations must be
// safe for sequential reuse across many CVEs within a single run.
type Classifier interface {
	Classify(ctx context.Context, cve mitigation.CVE) (Prediction, error)
	// Close releases any resources (model handles, HTTP clients).
	Close() error
}
