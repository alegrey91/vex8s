package inference

import (
	"fmt"
	"os"
	"path"

	_ "embed"

	ort "github.com/yalue/onnxruntime_go"
)

var (
	LABELS = []string{
		"arbitrary_file_write",
		"system_privileges_escalation",
		"resource_exhaustion",
		"arbitrary_file_read",
		"application_privileges_escalation",
		"application_crash",
	}
)

//go:embed nn/vex8s_cve_classifier.onnx
var onnxModel []byte

//go:embed nn/libonnxruntime.so
var onnxSO []byte

var ModelVersion = "unknown"

type Model struct {
	inputName  string
	outputName string
	Version    string
}

func NewModel() *Model {
	return &Model{
		Version: ModelVersion,
	}
}

func (m *Model) Setup() error {
	os.WriteFile(path.Join("/tmp", "libonnxruntime.so"), onnxSO, 0644)

	ort.SetSharedLibraryPath(path.Join("/tmp", "libonnxruntime.so"))

	err := ort.InitializeEnvironment()
	if err != nil {
		return fmt.Errorf("error initializing onnxruntime library: %v\n", err)
	}

	inputs, outputs, err := ort.GetInputOutputInfoWithONNXData(onnxModel)
	if err != nil {
		fmt.Printf("error getting input and output info for %s: %v\n", onnxModel, err)
		os.Exit(1)
	}
	m.inputName = inputs[0].Name
	m.outputName = outputs[0].Name

	return nil
}

func (m *Model) Destroy() {
	ort.DestroyEnvironment()
	os.Remove(path.Join("/tmp", "libonnxruntime.so"))
}

func (m *Model) Predict(inputText string) ([]string, error) {
	inputShape := ort.NewShape(1, 1)
	inputTensor, err := ort.NewStringTensor(inputShape)
	if err != nil {
		return []string{}, fmt.Errorf("failed to create input tensor: %v", err)
	}
	defer inputTensor.Destroy()

	inputTensor.SetElement(0, inputText)

	outputShape := ort.NewShape(1, int64(len(LABELS)))
	outputTensor, err := ort.NewEmptyTensor[int64](outputShape)
	if err != nil {
		return []string{}, fmt.Errorf("failed to create output tensor: %v", err)
	}
	defer outputTensor.Destroy()

	// to use embedded ONNX:
	session, err := ort.NewAdvancedSessionWithONNXData(
		onnxModel,
		[]string{m.inputName},
		[]string{m.outputName},
		[]ort.Value{inputTensor},
		[]ort.Value{outputTensor},
		nil, // options
	)
	if err != nil {
		return []string{}, fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Destroy()

	if err := session.Run(); err != nil {
		return []string{}, fmt.Errorf("failed to run inference: %v", err)
	}

	outputData := outputTensor.GetData()
	var matchingLabels []string
	for i, label := range LABELS {
		if i >= len(outputData) {
			break
		}

		val := outputData[i]

		if val >= 1 {
			matchingLabels = append(matchingLabels, label)
		}
	}

	if len(matchingLabels) > 0 {
		return matchingLabels, nil
	}

	return []string{"other"}, nil
}
