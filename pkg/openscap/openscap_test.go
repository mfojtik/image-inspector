package openscap

import (
	"fmt"
	"strings"
	"testing"

	docker "github.com/fsouza/go-dockerclient"

	iiapi "github.com/openshift/image-inspector/pkg/api"
)

func noRHELDist() (int, error) {
	return 0, fmt.Errorf("could not find RHEL dist")
}

func rhel7Dist() (int, error) {
	return 7, nil
}

func noInputCVE(int) (string, error) {
	return "", fmt.Errorf("No Input CVE")
}
func inputCVEMock(int) (string, error) {
	return "cve_file", nil
}

func unableToChroot(...string) ([]byte, error) {
	return []byte(""), fmt.Errorf("can't chroot")
}

func okChrootOscap(...string) ([]byte, error) {
	return []byte(""), nil
}

func rhel3OscapChroot(args ...string) ([]byte, error) {
	return []byte("oval:org.open-scap.cpe.rhel:def:3: true"), nil
}

func rhel7OscapChroot(args ...string) ([]byte, error) {
	if strings.Contains(args[3], "7") {
		return []byte("oval:org.open-scap.cpe.rhel:def:7: true"), nil
	}
	return []byte(""), nil
}

func TestGetRhelDist(t *testing.T) {

	tsRhel7ItIs := &defaultOSCAPScanner{chrootOscap: rhel7OscapChroot}
	tsRhel3Always := &defaultOSCAPScanner{chrootOscap: rhel3OscapChroot}
	noDistErr := fmt.Errorf("could not find RHEL dist")
	tsCantChroot := &defaultOSCAPScanner{chrootOscap: unableToChroot}
	_, cantChrootErr := unableToChroot()

	tests := map[string]struct {
		ts            *defaultOSCAPScanner
		shouldFail    bool
		expectedError error
		expectedDist  int
	}{
		"unable to chroot": {
			ts:            tsCantChroot,
			shouldFail:    true,
			expectedError: cantChrootErr,
		},
		"Always wrong dist": {
			ts:            tsRhel3Always,
			shouldFail:    true,
			expectedError: noDistErr,
		},
		"happy flow": {
			ts:           tsRhel7ItIs,
			shouldFail:   false,
			expectedDist: 7,
		},
	}

	for k, v := range tests {
		dist, err := v.ts.getRHELDist()
		if v.shouldFail && !strings.Contains(err.Error(), v.expectedError.Error()) {
			t.Errorf("%s expected  to cause error:\n%v\nBut got:\n%v", k, v.expectedError, err)
		}
		if !v.shouldFail && err != nil {
			t.Errorf("%s expected to succeed but failed with %v", k, err)
		}
		if !v.shouldFail && dist != v.expectedDist {
			t.Errorf("%s expected to succeed with dist=%d but got %d",
				k, v.expectedDist, dist)
		}
	}
}

func TestScan(t *testing.T) {
	tsNoRhelDist := &defaultOSCAPScanner{rhelDist: noRHELDist}
	_, noRhelDistErr := noRHELDist()

	tsNoInputCVE := &defaultOSCAPScanner{rhelDist: rhel7Dist, inputCVE: noInputCVE}
	_, noInputCVEErr := noInputCVE(0)

	tsCantChroot := &defaultOSCAPScanner{
		rhelDist:    rhel7Dist,
		inputCVE:    inputCVEMock,
		chrootOscap: unableToChroot,
	}
	_, cantChrootErr := unableToChroot()

	tsSuccessMocks := &defaultOSCAPScanner{
		rhelDist:    rhel7Dist,
		inputCVE:    inputCVEMock,
		chrootOscap: okChrootOscap,
	}

	tests := map[string]struct {
		ts            iiapi.Scanner
		shouldFail    bool
		expectedError error
	}{
		"cant find rhel dist": {
			ts:            tsNoRhelDist,
			shouldFail:    true,
			expectedError: noRhelDistErr,
		},
		"unable to get input cve": {
			ts:            tsNoInputCVE,
			shouldFail:    true,
			expectedError: noInputCVEErr,
		},
		"can't chroot to moutpath": {
			ts:            tsCantChroot,
			shouldFail:    true,
			expectedError: cantChrootErr,
		},
		"happy flow": {
			ts:         tsSuccessMocks,
			shouldFail: false,
		},
	}

	for k, v := range tests {
		_, err := v.ts.Scan(".", &docker.Image{})
		if v.shouldFail && !strings.Contains(err.Error(), v.expectedError.Error()) {
			t.Errorf("%s expected  to cause error:\n%v\nBut got:\n%v", k, v.expectedError, err)
		}
		if !v.shouldFail && err != nil {
			t.Errorf("%s expected to succeed but failed with %v", k, err)
		}
	}

	for k, v := range map[string]struct {
		mountPath string
		image     *docker.Image
	}{
		"mount path does not exist":     {"nosuchdir", &docker.Image{}},
		"mount path is not a directory": {"openscap.go", &docker.Image{}},
		"image is nil":                  {".", nil},
	} {
		if _, err := tsSuccessMocks.Scan(v.mountPath, v.image); err == nil {
			t.Errorf("%s did not fail", k)
		}
	}

}

func notEmptyValue(k, v string) error {
	if len(v) == 0 {
		return fmt.Errorf("the value should'nt be empty for key %s", k)
	}
	return nil
}

func TestSetOscapChrootEnv(t *testing.T) {
	oldSetVar := osSetEnv
	defer func() { osSetEnv = oldSetVar }()

	okImage := docker.Image{}
	okImage.Architecture = "x86_64"
	okImage.ID = "12345678901234567890"
	tsGoodImage := &defaultOSCAPScanner{image: &okImage, imageMountPath: "."}

	noArchImage := okImage
	noArchImage.Architecture = ""
	tsNoArch := &defaultOSCAPScanner{image: &noArchImage, imageMountPath: "."}

	shortIDImage := okImage
	shortIDImage.ID = "1234"
	tsShortID := &defaultOSCAPScanner{image: &shortIDImage, imageMountPath: "."}

	noIDImage := okImage
	noIDImage.ID = ""
	tsNoID := &defaultOSCAPScanner{image: &noIDImage, imageMountPath: "."}

	for k, v := range map[string]struct {
		ts *defaultOSCAPScanner
	}{
		"sanity check":       {ts: tsGoodImage},
		"no architecture":    {ts: tsNoArch},
		"short image ID":     {ts: tsShortID},
		"no image ID at all": {ts: tsNoID},
	} {
		osSetEnv = notEmptyValue
		err := v.ts.setOscapChrootEnv()
		if err != nil {
			t.Errorf("%s failed but shouldn't have. The error is %v", k, err)
		}
	}
}
