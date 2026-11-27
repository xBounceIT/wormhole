package updateauth

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"howett.net/plist"
)

const maxAssessmentBytes = 64 * 1024

func validateDarwinTeamID(team string) error {
	if len(team) != 10 || team == "0000000000" {
		return ErrPublisherUnavailable
	}
	for _, c := range team {
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return ErrPublisherUnavailable
		}
	}
	return nil
}

type darwinPublisherTool func(context.Context, string, ...string) ([]byte, error)

func verifyDarwinPublisher(file *os.File, team string, run darwinPublisherTool) error {
	if err := validateDarwinTeamID(team); err != nil {
		return err
	}
	path, err := filepath.Abs(file.Name())
	if err != nil || !strings.EqualFold(filepath.Ext(path), ".dmg") {
		return ErrArtifact
	}
	info, err := file.Stat()
	if err != nil || !sameDarwinDiskImage(path, info) {
		return ErrArtifact
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	requirement := `=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "` + team + `"`
	if _, err := run(ctx, "/usr/bin/codesign", "--verify", "--strict", "-R", requirement, path); err != nil {
		return ErrPublisherUntrusted
	}
	if !sameDarwinDiskImage(path, info) {
		return ErrArtifact
	}
	assessment, err := run(ctx, "/usr/sbin/spctl", "--assess", "--type", "open", "--context", "context:primary-signature", "--ignore-cache", "--no-cache", "--raw", path)
	if err != nil || !isNotarizedDarwinAssessment(assessment) {
		return ErrPublisherUntrusted
	}
	if !sameDarwinDiskImage(path, info) {
		return ErrArtifact
	}
	return nil
}

func sameDarwinDiskImage(path string, original os.FileInfo) bool {
	current, err := os.Lstat(path)
	return err == nil && current.Mode().IsRegular() && os.SameFile(original, current) &&
		current.Size() == original.Size() && current.ModTime().Equal(original.ModTime())
}

func isNotarizedDarwinAssessment(raw []byte) bool {
	if len(raw) == 0 || len(raw) > maxAssessmentBytes {
		return false
	}
	var result map[string]any
	if _, err := plist.Unmarshal(raw, &result); err != nil || result["assessment:verdict"] != true {
		return false
	}
	authority, ok := result["assessment:authority"].(map[string]any)
	if !ok || authority["assessment:authority:source"] != "Notarized Developer ID" {
		return false
	}
	_, override := authority["assessment:authority:override"]
	_, weak := authority["assessment:authority:weak"]
	return !override && !weak
}

func runDarwinPublisherTool(ctx context.Context, tool string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, tool, args...)
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin:/bin", "LC_ALL=C"}
	cmd.WaitDelay = time.Second
	var output assessmentOutput
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return output.buffer.Bytes(), nil
}

type assessmentOutput struct{ buffer bytes.Buffer }

func (o *assessmentOutput) Write(data []byte) (int, error) {
	if len(data) > maxAssessmentBytes-o.buffer.Len() {
		return 0, io.ErrShortBuffer
	}
	return o.buffer.Write(data)
}
