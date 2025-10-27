package mitigation

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func boolPtr(v bool) *bool {
	return &v
}

func Test_hasReadOnlyRootFileSystem(t *testing.T) {
	tests := []struct {
		name string
		c    *corev1.Container
		want bool
	}{
		{
			name: "readOnlyRootFileSystem true",
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{
					ReadOnlyRootFilesystem: boolPtr(true),
				},
			},
			want: true,
		},
		{
			name: "readOnlyRootFileSystem false",
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{
					ReadOnlyRootFilesystem: boolPtr(false),
				},
			},
			want: false,
		},
		{
			name: "readOnlyRootFileSystem not set",
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasReadOnlyRootFileSystem(tt.c)
			if tt.want != got {
				t.Errorf("hasReadOnlyRootFileSystem() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_hasVolumeMountReadOnly(t *testing.T) {
	tests := []struct {
		name string
		c    *corev1.Container
		want bool
	}{
		{
			name: "volumeMount.readOnly is true",
			c: &corev1.Container{
				VolumeMounts: []corev1.VolumeMount{
					{
						ReadOnly: true,
					},
				},
			},
			want: true,
		},
		{
			name: "volumeMount.readOnly is false",
			c: &corev1.Container{
				VolumeMounts: []corev1.VolumeMount{
					{
						ReadOnly: false,
					},
				},
			},
			want: false,
		},
		{
			name: "no volumeMounts are present",
			c:    &corev1.Container{},
			want: true,
		},
		{
			name: "volumeMount.readOnly has one value false",
			c: &corev1.Container{
				VolumeMounts: []corev1.VolumeMount{
					{
						ReadOnly: true,
					},
					{
						ReadOnly: true,
					},
					{
						ReadOnly: false,
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasVolumeMountReadOnly(tt.c)
			if tt.want != got {
				t.Errorf("hasVolumeMountReadOnly() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_hasCapabilitiesDropAll(t *testing.T) {
	tests := []struct {
		name string
		c    *corev1.Container
		want bool
	}{
		{
			name: "capabilities.Drop is ALL",
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{
							corev1.Capability("ALL"),
						},
					},
				},
			},
			want: true,
		},
		{
			name: "capabilities.Drop is not set",
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{},
					},
				},
			},
			want: false,
		},
		{
			name: "capabilities.Drop does not contains ALL",
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{
							corev1.Capability("NET_ADMIN"),
							corev1.Capability("SYS_TIME"),
						},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasCapabilitiesDropAll(tt.c)
			if tt.want != got {
				t.Errorf("hasCapabilitiesDropAll() = %v, want %v", got, tt.want)
			}
		})
	}
}
