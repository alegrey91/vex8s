package k8s

import (
	"fmt"
	"os"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/scheme"
)

// ParseManifestPodSpec reads a Kubernetes manifest file and extracts the PodSpec
// Supported kinds: Job, Deployment, StatefulSet, DaemonSet, CronJob, Pod
func ParseManifestPodSpec(manifestPath string) (*corev1.PodSpec, error) {
	// Read the manifest file
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}

	// Create a decoder
	decode := serializer.NewCodecFactory(scheme.Scheme).UniversalDeserializer().Decode

	// Decode the manifest
	obj, gvk, err := decode(data, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decode manifest: %w", err)
	}

	// Extract PodSpec based on the Kind
	switch gvk.Kind {
	case "Pod":
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			return nil, fmt.Errorf("failed to cast to Pod")
		}
		return &pod.Spec, nil

	case "Deployment":
		deployment, ok := obj.(*appsv1.Deployment)
		if !ok {
			return nil, fmt.Errorf("failed to cast to Deployment")
		}
		return &deployment.Spec.Template.Spec, nil

	case "StatefulSet":
		statefulSet, ok := obj.(*appsv1.StatefulSet)
		if !ok {
			return nil, fmt.Errorf("failed to cast to StatefulSet")
		}
		return &statefulSet.Spec.Template.Spec, nil

	case "DaemonSet":
		daemonSet, ok := obj.(*appsv1.DaemonSet)
		if !ok {
			return nil, fmt.Errorf("failed to cast to DaemonSet")
		}
		return &daemonSet.Spec.Template.Spec, nil

	case "Job":
		job, ok := obj.(*batchv1.Job)
		if !ok {
			return nil, fmt.Errorf("failed to cast to Job")
		}
		return &job.Spec.Template.Spec, nil

	case "CronJob":
		cronJob, ok := obj.(*batchv1.CronJob)
		if !ok {
			return nil, fmt.Errorf("failed to cast to CronJob")
		}
		return &cronJob.Spec.JobTemplate.Spec.Template.Spec, nil

	default:
		return nil, fmt.Errorf("unsupported kind: %s (supported: Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob)", gvk.Kind)
	}
}
