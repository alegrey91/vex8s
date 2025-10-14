package llm

import (
	"bytes"
	_ "embed"
	"text/template"

	"github.com/alegrey91/vex8s/pkg/classifier"
	"github.com/alegrey91/vex8s/pkg/trivy"
)

//go:embed prompt.tpl
var templatePrompt string

type TemplateData struct {
	CVEList       []trivy.CVE
	VulnClassList []classifier.Class
	Schema        string
}

func (td *TemplateData) GeneratePrompt() string {
	var buf bytes.Buffer
	t := template.Must(template.New("prompt").Parse(templatePrompt))
	err := t.Execute(&buf, td)
	if err != nil {
		panic(err)
	}
	return buf.String()
}
