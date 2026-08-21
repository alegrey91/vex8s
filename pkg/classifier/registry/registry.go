// Package registry constructs classifier backends by engine name. It is kept
// separate from pkg/classifier so that backends can import the classifier
// interface without creating an import cycle.
package registry

import (
	"fmt"

	"github.com/alegrey91/vex8s/pkg/classifier"
	"github.com/alegrey91/vex8s/pkg/classifier/embedded"
)

// Engine identifies a classifier backend selectable by the user.
type Engine string

const (
	// EngineEmbedded is the built-in ONNX ML model.
	EngineEmbedded Engine = "embedded"
	// EngineAnthropic is a placeholder for the future Anthropic LLM backend.
	// It is intentionally not implemented yet; see New.
	EngineAnthropic Engine = "anthropic"
)

// Options carries backend-specific configuration. LLM backends will read fields
// added here (model id, API key source, min confidence) without changing the
// New signature.
type Options struct {
	Engine Engine
}

// New constructs the classifier for the requested engine.
//
// To add an LLM backend (e.g. Anthropic): implement classifier.Classifier in
// pkg/classifier/anthropic, then add a case here that constructs it from opts.
// The rest of the pipeline consumes the classifier.Classifier interface and
// needs no changes.
func New(opts Options) (classifier.Classifier, error) {
	switch opts.Engine {
	case EngineEmbedded, "":
		return embedded.New()
	case EngineAnthropic:
		return nil, fmt.Errorf("classifier engine %q is not implemented yet", opts.Engine)
	default:
		return nil, fmt.Errorf("unknown classifier engine %q", opts.Engine)
	}
}
