/*
Copyright © 2026 Alessio Greggi
*/
package cmd

import (
	"fmt"

	"github.com/alegrey91/vex8s/pkg/inference"
	"github.com/spf13/cobra"
)

var (
	showModelVersion bool
	predictLabels    string
)

var modelCmd = &cobra.Command{
	Use:   "model",
	Short: "Show information about the ML model used by vex8s",
	RunE: func(cmd *cobra.Command, args []string) error {
		model := inference.NewModel()

		if showModelVersion {
			fmt.Printf("Model version: %s\n", model.Version)
			return nil
		}

		if predictLabels != "" {
			if err := model.Setup(); err != nil {
				return fmt.Errorf("[!] Error: setting up model: %w", err)
			}
			defer model.Destroy()

			labels := model.Predict(predictLabels)
			fmt.Printf("Predicted labels: %v\n", labels)
			return nil
		}

		return cmd.Help()
	},
}

func init() {
	modelCmd.Flags().BoolVarP(&showModelVersion, "version", "v", false, "Show the model version")
	modelCmd.Flags().StringVarP(&predictLabels, "predict", "p", "", "Predict labels for the given input")
	rootCmd.AddCommand(modelCmd)
}
