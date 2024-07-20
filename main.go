package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/anchore/go-collections"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/sourceproviders"
	"github.com/olekukonko/tablewriter"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/ollama"
)

func main() {
	var image string
	var outputFormat string
	var serverMode bool
	var generateRecommendations bool

	rootCmd := &cobra.Command{
		Use:   "sbominsight",
		Short: "sbominsight generates SBOM from container images and directories",
		Run: func(cmd *cobra.Command, args []string) {
			if serverMode {
				startServer()
				return
			}

			if image == "" {
				logrus.Error("Image reference is required to generate SBOM")
				os.Exit(1)
			}

			// Get the source based on the input image reference
			src := getSource(image)

			// Catalog the given source and return an SBOM
			sbom := getSBOM(src, pkgcataloging.InstalledTag, pkgcataloging.DirectoryTag, pkgcataloging.ImageTag)

			// Print the SBOM in the specified format
			printSBOM(sbom, outputFormat)

			// Print cataloged contents information
			printCatalogedContents(sbom)

			// Generate and print SBOM recommendations if the flag is set
			if generateRecommendations {
				recommendations := getVulnerabilityRemediations(sbom)
				fmt.Println("Vulnerability Remediations:")
				fmt.Println(recommendations)
			}
		},
	}

	rootCmd.Flags().StringVarP(&image, "image", "i", "", "Image reference to generate SBOM from")
	rootCmd.Flags().StringVarP(&outputFormat, "output", "o", "json", "Output format (json, table)")
	rootCmd.Flags().BoolVarP(&serverMode, "server", "s", false, "Run in server mode")
	rootCmd.Flags().BoolVarP(&generateRecommendations, "recommendations", "r", false, "Generate vulnerability and remediation recommendations")

	if err := rootCmd.Execute(); err != nil {
		logrus.Fatalf("Error executing command: %v", err)
	}
}

// startServer starts the HTTP server to serve SBOM data
func startServer() {
	http.HandleFunc("/sbom", func(w http.ResponseWriter, r *http.Request) {
		image := r.URL.Query().Get("image")
		if image == "" {
			http.Error(w, "Image reference is required", http.StatusBadRequest)
			return
		}

		src := getSource(image)
		sbom := getSBOM(src, pkgcataloging.InstalledTag, pkgcataloging.DirectoryTag, pkgcataloging.ImageTag)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(transformSBOM(sbom))
	})

	fmt.Println("Server is running on http://localhost:8080")
	logrus.Fatal(http.ListenAndServe(":8080", nil))
}

// sanitizeFilename replaces special characters in a string to create a valid filename
func sanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, ":", "_")
	return name
}

// allSourceTags returns all source tags
func allSourceTags() []string {
	return collections.TaggedValueSet[source.Provider]{}.Join(sourceproviders.All("", nil)...).Tags()
}

// getSource retrieves a source object based on the input reference
func getSource(input string) source.Source {
	src, err := syft.GetSource(context.Background(), input, nil)
	if err != nil {
		panic(err)
	}
	return src
}

// getSBOM generates an SBOM for the given source with specified cataloger tags
func getSBOM(src source.Source, defaultTags ...string) sbom.SBOM {
	cfg := syft.DefaultCreateSBOMConfig().
		WithCatalogerSelection(
			pkgcataloging.NewSelectionRequest().
				WithDefaults(defaultTags...),
		)

	// Generate SBOM using syft
	s, err := syft.CreateSBOM(context.Background(), src, cfg)
	if err != nil {
		panic(err)
	}

	return *s
}

// printSBOM prints the SBOM in the specified format
func printSBOM(s sbom.SBOM, format string) {
	switch format {
	case "json":
		printSBOMAsJSON(s)
	case "table":
		printSBOMAsTable(s)
	default:
		logrus.Fatalf("Unsupported output format: %s", format)
	}
}

// printSBOMAsJSON prints the SBOM in JSON format
func printSBOMAsJSON(s sbom.SBOM) {
	// Transform the SBOM to a JSON-friendly format
	serializableSBOM := transformSBOM(s)

	// Print the SBOM in JSON format
	data, err := json.MarshalIndent(serializableSBOM, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding SBOM: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

// printSBOMAsTable prints the SBOM in table format
func printSBOMAsTable(s sbom.SBOM) {
	// Create a new table writer
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Name", "Version", "Type"})

	// Transform packages for table output
	for _, pkg := range s.Artifacts.Packages.Sorted() {
		table.Append([]string{string(pkg.ID()), pkg.Name, pkg.Version, string(pkg.Type)})
	}

	// Render the table to the standard output
	table.Render()
}

// printCatalogedContents prints cataloged contents information
func printCatalogedContents(s sbom.SBOM) {
	fmt.Println("Cataloged contents:")
	fmt.Printf("  ✔ Packages\t\t\t\t[%d packages]\n", len(s.Artifacts.Packages.Sorted()))
	fmt.Printf("  ✔ File digests\t\t\t[%d files]\n", len(s.Artifacts.FileDigests))
	fmt.Printf("  ✔ File metadata\t\t\t[%d locations]\n", len(s.Artifacts.FileMetadata))
	fmt.Printf("  ✔ Executables\t\t\t\t[%d executables]\n", len(s.Artifacts.Executables))
}

// transformSBOM transforms the SBOM to a JSON-friendly format
func transformSBOM(s sbom.SBOM) interface{} {
	type FileMetadata struct {
		Path     string
		MIMEType string
	}

	type Package struct {
		ID      string
		Name    string
		Version string
		Type    string
	}

	type SerializableSBOM struct {
		Artifacts struct {
			Packages     []Package
			FileMetadata map[string]FileMetadata
		}
		Source     interface{}
		Descriptor interface{}
	}

	serializableSBOM := SerializableSBOM{}

	// Transform packages
	for _, pkg := range s.Artifacts.Packages.Sorted() {
		serializableSBOM.Artifacts.Packages = append(serializableSBOM.Artifacts.Packages, Package{
			ID:      string(pkg.ID()),
			Name:    pkg.Name,
			Version: pkg.Version,
			Type:    string(pkg.Type),
		})
	}

	// Transform file metadata
	serializableSBOM.Artifacts.FileMetadata = make(map[string]FileMetadata)
	for coords, metadata := range s.Artifacts.FileMetadata {
		serializableSBOM.Artifacts.FileMetadata[coords.RealPath] = FileMetadata{
			Path:     coords.RealPath,
			MIMEType: metadata.MIMEType,
		}
	}

	// Include source and descriptor as they are
	serializableSBOM.Source = s.Source
	serializableSBOM.Descriptor = s.Descriptor

	return serializableSBOM
}

// getVulnerabilityRemediations generates vulnerability and remediation recommendations based on the SBOM using langchaingo
func getVulnerabilityRemediations(s sbom.SBOM) string {
	// Transform the SBOM to a JSON-friendly format
	serializableSBOM := transformSBOM(s)

	// Convert the SBOM to JSON
	sbomJSON, err := json.Marshal(serializableSBOM)
	if err != nil {
		logrus.Fatalf("Error marshaling SBOM: %v", err)
	}

	// Initialize the Ollama LLM client directly without an API key
	llm, err := ollama.New(ollama.WithModel("llama2"))
	if err != nil {
		logrus.Fatalf("Error creating Ollama client: %v", err)
	}

	// Create a context
	ctx := context.Background()

	// Create a prompt for generating vulnerability and remediation recommendations
	prompt := fmt.Sprintf("Based on the following SBOM JSON, identify the vulnerabilities and provide recommendations for remediation:\n%s", string(sbomJSON))

	// Generate completion with streaming output
	var recommendations string
	_, err = llm.Call(ctx, prompt,
		llms.WithTemperature(0.8),
		llms.WithStreamingFunc(func(ctx context.Context, chunk []byte) error {
			recommendations += string(chunk)
			return nil
		}),
	)
	if err != nil {
		logrus.Fatalf("Error generating recommendations: %v", err)
	}

	return recommendations
}
