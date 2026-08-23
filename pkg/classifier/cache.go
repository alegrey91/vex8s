package classifier

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/alegrey91/vex8s/pkg/mitigation"
)

// caching wraps a Classifier and memoizes predictions by CVE ID. A CVE's
// exploitation class depends only on the vulnerability itself (description,
// CWEs), never on the container it ships in, so the same CVE appearing across
// multiple packages or containers is classified once and reused. This is a
// no-op for cheap backends but avoids redundant work for expensive ones such as
// LLM-backed engines that hit a remote API per call.
type caching struct {
	inner    Classifier
	showLogs bool

	mu    sync.Mutex
	cache map[string]Prediction
}

// Cached returns a Classifier that memoizes inner's predictions by CVE ID. When
// showLogs is true, cache hits are reported to stderr.
func Cached(inner Classifier, showLogs bool) Classifier {
	return &caching{inner: inner, showLogs: showLogs, cache: map[string]Prediction{}}
}

func (c *caching) Classify(ctx context.Context, cve mitigation.CVE) (Prediction, error) {
	c.mu.Lock()
	if p, ok := c.cache[cve.ID]; ok {
		c.mu.Unlock()
		if c.showLogs {
			fmt.Fprintf(os.Stderr, "[*] classifier: cache hit for %s\n", cve.ID)
		}
		return p, nil
	}
	c.mu.Unlock()

	p, err := c.inner.Classify(ctx, cve)
	if err != nil {
		return p, err
	}

	c.mu.Lock()
	c.cache[cve.ID] = p
	c.mu.Unlock()
	return p, nil
}

func (c *caching) Close() error {
	return c.inner.Close()
}
