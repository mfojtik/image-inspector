package clamav

import (
	"fmt"
	"log"
	"strings"
	"time"

	clamd "github.com/dutchcoders/go-clamd"
	"github.com/fsouza/go-dockerclient"

	"github.com/openshift/image-inspector/pkg/api"
)

type ClamScanner struct {
	// Socket is the location of the clamav socket.
	Socket string
}

var _ api.Scanner = &ClamScanner{}

func NewScanner(socket string) api.Scanner {
	return &ClamScanner{
		Socket: socket,
	}
}

// Scan will scan the image
func (s *ClamScanner) Scan(path string, image *docker.Image) ([]api.Result, error) {
	scanner := clamd.NewClamd(s.Socket)

	versionChan, err := scanner.Version()
	if err != nil {
		return nil, err
	}
	scannerVersion := <-versionChan

	// Useful for debugging
	scanStarted := time.Now()
	defer func() {
		log.Printf("ClamAv scan took %ds", int64(time.Since(scanStarted).Seconds()))
	}()
	resultChan, err := scanner.ContScanFile(path)
	if err != nil {
		return nil, err
	}

	scanResults := []api.Result{}

	// The scan is done when clam send empty result back?
	scanDone := false
	for !scanDone {
		select {
		case scanResult := <-resultChan:
			if scanResult == nil {
				scanDone = true
				break
			}
			r := api.Result{
				Name:           "clamav",
				ScannerVersion: scannerVersion.Raw,
				Timestamp:      scanStarted,
				Reference:      fmt.Sprintf("file://%s", strings.TrimPrefix(scanResult.Path, path)),
				Description:    scanResult.Description,
			}
			scanResults = append(scanResults, r)
		}
	}

	return scanResults, nil
}

// ScannerName is the scanner's name
func (s *ClamScanner) ScannerName() string {
	return "ClamAV"
}

// ResultFileName returns the name of the results file
func (s *ClamScanner) ResultsFileName() string {
	return ""
}

// HtmlResultFileName returns the name of the results file
func (s *ClamScanner) HTMLResultsFileName() string {
	return ""
}
