package api

import (
	"time"

	docker "github.com/fsouza/go-dockerclient"
)

// OpenSCAPStatus is the status of openscap scan
type OpenSCAPStatus string

const (
	StatusNotRequested OpenSCAPStatus = "NotRequested"
	StatusSuccess      OpenSCAPStatus = "Success"
	StatusError        OpenSCAPStatus = "Error"
)

// ScanResult represents the compacted result of all scans performed on the image
type ScanResult struct {
	// ImageName is a full pull spec of the input image
	ImageName string `json:"imageName"`
	// ImageIUD is a SHA256 identifier of the scanned image
	ImageID string `json:"imageID"`
	// Results contains compacted results of various scans performed on the image.
	// Empty results means no problems were found with the given image.
	Results []Result `json:"results,omitempty"`
}

// Result represents the compacted result of a single scan
type Result struct {
	// Name is the name of the scanner that produced this result
	Name string `json:"name"`
	// ScannerVersion is the scanner version
	ScannerVersion string `json:"scannerVersion"`
	// Timestamp is the exact time this scan was performed
	Timestamp time.Time `json:"timestamp"`
	// Reference contains URL to more details about the given result
	Reference string `json:"reference"`
	// Description describes the result in human readable form
	Description string `json:"description,omitempty"`
	// Summary contains a list of severities for the given result
	Summary []Summary `json:"summary,omitempty"`
}

type Severity string

var (
	LowSeverity       Severity = "low"
	MediumSeverity    Severity = "medium"
	ImportantSeverity Severity = "important"
	HighSeverity      Severity = "high"
)

// Summary represents a severy of a given result. The result can have multiple severieties
// defined.
type Summary struct {
	// Label is the human readable severity (high, important, etc.)
	Label Severity
}

type OpenSCAPMetadata struct {
	Status           OpenSCAPStatus // Status of the OpenSCAP scan report
	ErrorMessage     string         // Error message from the openscap
	ContentTimeStamp string         // Timestamp for this data
}

func (osm *OpenSCAPMetadata) SetError(err error) {
	osm.Status = StatusError
	osm.ErrorMessage = err.Error()
	osm.ContentTimeStamp = string(time.Now().Format(time.RFC850))
}

var (
	ScanOptions = []string{"openscap"}
)

// InspectorMetadata is the metadata type with information about image-inspector's operation
type InspectorMetadata struct {
	docker.Image // Metadata about the inspected image
	// OpenSCAP describes the state of the OpenSCAP scan
	OpenSCAP *OpenSCAPMetadata
}

// APIVersions holds a slice of supported API versions.
type APIVersions struct {
	// Versions is the supported API versions
	Versions []string `json:"versions"`
}

// Scanner interface that all scanners should define.
type Scanner interface {
	// Scan will scan the image
	Scan(string, *docker.Image) error
	// ScannerName is the scanner's name
	ScannerName() string
	// ResultFileName returns the name of the results file
	ResultsFileName() string
	// HtmlResultFileName returns the name of the results file
	HTMLResultsFileName() string
}
