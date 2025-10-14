package classifier_test

import (
	"fmt"
	"testing"

	"github.com/alegrey91/vex8s/pkg/classifier"
	"github.com/alegrey91/vex8s/pkg/trivy"
	corev1 "k8s.io/api/core/v1"
)

func falsePtr() *bool {
	a := false
	return &a
}

func truePtr() *bool {
	a := true
	return &a
}

func TestClass_IsCVEMitigated(t *testing.T) {
	type input struct {
		cve      classifier.ClassifiedCVE
		manifest *corev1.PodSpec
	}
	tests := []struct {
		name  string // description of this test case
		input input
		want  bool
	}{
		{
			name: "Container Escape",
			input: input{
				cve: classifier.ClassifiedCVE{
					CVE: &trivy.CVE{
						ID: "CVE-2025-00001",
					},
					Classes: []classifier.Class{
						{
							Name: classifier.ContainerEscape,
						},
					},
				},
				manifest: &corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: "container_1",
							SecurityContext: &corev1.SecurityContext{
								Privileged:             falsePtr(),
								ReadOnlyRootFilesystem: truePtr(),
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{
										corev1.Capability("ALL"),
									},
								},
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "Filesystem Manipulation",
			input: input{
				cve: classifier.ClassifiedCVE{
					CVE: &trivy.CVE{
						ID: "CVE-2025-00002",
					},
					Classes: []classifier.Class{
						{
							Name: classifier.FilesystemManipulation,
						},
					},
				},
				manifest: &corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: "container_1",
							SecurityContext: &corev1.SecurityContext{
								ReadOnlyRootFilesystem: truePtr(),
								RunAsNonRoot:           truePtr(),
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{
										corev1.Capability("ALL"),
									},
								},
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "None",
			input: input{
				cve: classifier.ClassifiedCVE{
					CVE: &trivy.CVE{
						ID: "CVE-2025-00003",
					},
					Classes: []classifier.Class{
						{
							Name: classifier.RootOnly,
						},
					},
				},
				manifest: &corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: "container_1",
							SecurityContext: &corev1.SecurityContext{
								Privileged: falsePtr(),
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{
										corev1.Capability("ALL"),
									},
								},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name: "Filesystem Manipulation",
			input: input{
				cve: classifier.ClassifiedCVE{
					CVE: &trivy.CVE{
						ID: "CVE-2025-00004",
					},
					Classes: []classifier.Class{
						{
							Name: classifier.RootOnly,
						},
					},
				},
				manifest: &corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: "container_1",
							SecurityContext: &corev1.SecurityContext{
								ReadOnlyRootFilesystem: truePtr(),
								RunAsNonRoot:           truePtr(),
							},
						},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifier.IsCVEMitigated(tt.input.cve, tt.input.manifest)
			fmt.Println("CVE mitigated:", got, "wanted:", tt.want)
			if tt.want != got {
				fmt.Println("unexpected error for test:", tt.name)
			}
		})
	}
}
