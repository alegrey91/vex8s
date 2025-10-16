package prompt_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/alegrey91/vex8s/pkg/classifier"
	prompt "github.com/alegrey91/vex8s/pkg/prompt"
	"github.com/alegrey91/vex8s/pkg/trivy"
)

func TestTemplateData_GeneratePrompt(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		td   prompt.TemplateData
		want string
	}{
		{
			name: "test 1",
			td: prompt.TemplateData{
				CVEList: []trivy.CVE{
					{
						ID:          "CVE-2025-1234",
						Description: "description of cve-2025-1234",
					},
					{
						ID:          "CVE-2025-12345",
						Description: "description of cve-2025-12345",
					},
				},
				VulnClassList: classifier.Classes,
			},
			want: "description of class_test_1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: construct the receiver type.
			got := tt.td.GeneratePrompt()
			fmt.Println(got)
			if strings.Contains(tt.want, got) {
				t.Errorf("GeneratePrompt() = %v, want %v", got, tt.want)
			}
		})
	}
}
