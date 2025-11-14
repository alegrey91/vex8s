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

func Test_hasRunAsNonRoot(t *testing.T) {
	tests := []struct {
		name string
		p    *corev1.PodSpec
		c    *corev1.Container
		want bool
	}{
		{
			name: "runAsNonRoot is true",
			p: &corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					RunAsNonRoot: boolPtr(true),
				},
			},
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{
					RunAsNonRoot: boolPtr(true),
				},
			},
			want: true,
		},
		{
			name: "runAsNonRoot is false",
			p: &corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					RunAsNonRoot: boolPtr(false),
				},
			},
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{
					RunAsNonRoot: boolPtr(false),
				},
			},
			want: false,
		},
		{
			name: "runAsNonRoot is not set at podSpec / runAsNonRoot is true at container",
			p: &corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{},
			},
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{
					RunAsNonRoot: boolPtr(true),
				},
			},
			want: true,
		},
		{
			name: "runAsNonRoot is true at podSpec / runAsNonRoot is not set at container",
			p: &corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					RunAsNonRoot: boolPtr(true),
				},
			},
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{},
			},
			want: true,
		},
		{
			name: "runAsNonRoot is not set at podSpec and container",
			p: &corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{},
			},
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{},
			},
			want: false,
		},
		{
			name: "runAsNonRoot is true at container but false at podSpec",
			p: &corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					RunAsNonRoot: boolPtr(false),
				},
			},
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{
					RunAsNonRoot: boolPtr(true),
				},
			},
			want: true,
		},
		{
			name: "runAsNonRoot is false at container but true at podSpec",
			p: &corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					RunAsNonRoot: boolPtr(true),
				},
			},
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{
					RunAsNonRoot: boolPtr(false),
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasRunAsNonRoot(tt.p, tt.c)
			if tt.want != got {
				t.Errorf("hasRunAsNonRoot() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_hasHostPath(t *testing.T) {
	tests := []struct {
		name string
		p    *corev1.PodSpec
		want bool
	}{
		{
			name: "hostPath not present",
			p: &corev1.PodSpec{
				Volumes: []corev1.Volume{
					{
						Name:         "test_volume_1",
						VolumeSource: corev1.VolumeSource{},
					},
				},
			},
			want: false,
		},
		{
			name: "hostPath is set",
			p: &corev1.PodSpec{
				Volumes: []corev1.Volume{
					{
						Name: "test_volume_1",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/etc",
							},
						},
					},
				},
			},
			want: true,
		},
		{
			name: "hostPath is set with multiple volumens",
			p: &corev1.PodSpec{
				Volumes: []corev1.Volume{
					{
						Name:         "test_volume_1",
						VolumeSource: corev1.VolumeSource{},
					},
					{
						Name: "test_volume_1",
						VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{
								Path: "/etc",
							},
						},
					},
					{
						Name:         "test_volume_1",
						VolumeSource: corev1.VolumeSource{},
					},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasHostPath(tt.p)
			if tt.want != got {
				t.Errorf("hasHostPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_hasSeccompProfileTypeRuntimeDefault(t *testing.T) {
	tests := []struct {
		name string
		p    *corev1.PodSpec
		c    *corev1.Container
		want bool
	}{
		{
			name: "has no seccomp profile set",
			p:    &corev1.PodSpec{},
			c:    &corev1.Container{},
			want: false,
		},
		{
			name: "has seccomp profile set to podspec",
			p: &corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{
					SeccompProfile: &corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					},
				},
			},
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{},
			},
			want: true,
		},
		{
			name: "has seccomp profile set to container",
			p: &corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{},
			},
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{
					SeccompProfile: &corev1.SeccompProfile{
						Type: corev1.SeccompProfileTypeRuntimeDefault,
					},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasSeccompProfileTypeRuntimeDefault(tt.p, tt.c)
			if got != tt.want {
				t.Errorf("hasSeccompProfileTypeRuntimeDefault() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_hasCapabilitiesAddContains(t *testing.T) {
	tests := []struct {
		name         string
		c            *corev1.Container
		capabilities []string
		want         bool
	}{
		{
			name: "capabilities.add has no input capabilities",
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{
							"CAP_CHOWN",
							"CAP_SETUID",
							"CAP_SETGID",
							"CAP_NET_BIND_SERVICE",
						},
					},
				},
			},
			capabilities: []string{
				"CAP_NET_ADMIN",
				"CAP_SYS_MODULE",
			},
			want: false,
		},
		{
			name: "capabilities.add has input capabilities",
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{
							"CAP_CHOWN",
							"CAP_SETUID",
							"CAP_SETGID",
							"CAP_NET_BIND_SERVICE",
						},
					},
				},
			},
			capabilities: []string{
				"CAP_SETGID",
			},
			want: true,
		},
		{
			name: "capabilities.add does not have capabilities set",
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{},
			},
			capabilities: []string{
				"CAP_SETGID",
			},
			want: false,
		},
		{
			name: "input capabilities is empty",
			c: &corev1.Container{
				SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{
						Add: []corev1.Capability{
							"CAP_CHOWN",
							"CAP_SETUID",
							"CAP_SETGID",
							"CAP_NET_BIND_SERVICE",
						},
					},
				},
			},
			capabilities: []string{},
			want:         false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasCapabilitiesAddContains(tt.c, tt.capabilities)
			if tt.want != got {
				t.Errorf("hasCapabilitiesAddContains() = %v, want %v", got, tt.want)
			}
		})
	}
}
