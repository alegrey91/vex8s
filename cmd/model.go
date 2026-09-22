/*
Copyright © 2026 Alessio Greggi
*/
package cmd

import (
	"context"
	"fmt"

	"github.com/alegrey91/vex8s/pkg/classifier"
	"github.com/alegrey91/vex8s/pkg/classifier/registry"
	"github.com/alegrey91/vex8s/pkg/inference"
	"github.com/alegrey91/vex8s/pkg/mitigation"
	"github.com/spf13/cobra"
)

var (
	showModelVersion bool
	predictLabels    string
	modelClassifier  string
	showPrompt       bool
)

var modelCmd = &cobra.Command{
	Use:   "model",
	Short: "Show information about the ML model used by vex8s",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if err := registry.Validate(registry.Options{Engine: registry.Engine(modelClassifier)}); err != nil {
			return fmt.Errorf("[!] Error: %w", err)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if showModelVersion {
			fmt.Printf("Model version: %s\n", inference.NewModel().Version)
			return nil
		}

		if showPrompt {
			fmt.Println("========================================")
			switch registry.Engine(modelClassifier) {
			case registry.EngineGemini, registry.EngineOllama:
				fmt.Println(classifier.BuildPrompt(mitigation.CVE{Description: predictLabels}))
			default:
				fmt.Println("the embedded model doesn't have a prompt")
			}
			fmt.Println("========================================")
		}

		if predictLabels != "" {
			clf, err := registry.New(registry.Options{Engine: registry.Engine(modelClassifier)})
			if err != nil {
				return fmt.Errorf("[!] Error: setting up classifier: %w", err)
			}
			defer clf.Close()

			prediction, err := clf.Classify(context.Background(), mitigation.CVE{Description: predictLabels})
			if err != nil {
				return fmt.Errorf("[!] Error: classifier prediction: %w", err)
			}

			fmt.Printf("Predicted labels: %v\n", prediction.Classes)
			return nil
		}

		return cmd.Help()
	},
}

func init() {
	modelCmd.Flags().BoolVarP(&showModelVersion, "version", "v", false, "Show the model version")
	modelCmd.Flags().StringVarP(&predictLabels, "predict", "p", "", "Predict labels for the given input")
	modelCmd.Flags().StringVar(&modelClassifier, "classifier", "embedded", "classifier engine [embedded, gemini, ollama]")
	modelCmd.Flags().BoolVar(&showPrompt, "show.prompt", false, "Show the prompt used to query the classifier (LLM engines only)")
	rootCmd.AddCommand(modelCmd)
}
