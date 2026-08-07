package main

import (
	"archive/zip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

type safeZipExtractionOptions struct {
	maxEntries           int
	maxExtractedBytes    int64
	unsafePathError      string
	unsupportedTypeError string
	tooManyEntriesError  string
	tooLargeError        string
	extractionError      string
}

func extractZipSafely(zipPath, destinationRoot string, options safeZipExtractionOptions) error {
	archive, err := zip.OpenReader(zipPath)
	if err != nil {
		return errors.New("The selected file is not a valid ZIP archive.")
	}
	defer func() { _ = archive.Close() }()

	if len(archive.File) > options.maxEntries {
		return errors.New(options.tooManyEntriesError)
	}
	fullRoot, err := filepath.Abs(destinationRoot)
	if err != nil {
		return errors.New(options.extractionError)
	}
	fullRoot = filepath.Clean(fullRoot)
	extracted := int64(0)
	for _, entry := range archive.File {
		cleanName := filepath.Clean(filepath.FromSlash(entry.Name))
		if cleanName == "." {
			continue
		}
		if filepath.IsAbs(cleanName) ||
			unsafePortableZipPath(cleanName) ||
			cleanName == ".." ||
			strings.HasPrefix(cleanName, ".."+string(filepath.Separator)) {
			return errors.New(options.unsafePathError)
		}
		target := filepath.Join(fullRoot, cleanName)
		if !strings.HasPrefix(target, fullRoot+string(filepath.Separator)) {
			return errors.New(options.unsafePathError)
		}
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return errors.New(options.extractionError)
			}
			continue
		}
		if entry.Mode()&os.ModeType != 0 {
			return errors.New(options.unsupportedTypeError)
		}
		if entry.UncompressedSize64 > uint64(options.maxExtractedBytes) {
			return errors.New(options.tooLargeError)
		}
		expectedSize := int64(entry.UncompressedSize64)
		if extracted > options.maxExtractedBytes-expectedSize {
			return errors.New(options.tooLargeError)
		}
		extracted += expectedSize
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return errors.New(options.extractionError)
		}
		reader, err := entry.Open()
		if err != nil {
			return errors.New(options.extractionError)
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			_ = reader.Close()
			return errors.New(options.extractionError)
		}
		written, copyErr := io.Copy(output, io.LimitReader(reader, expectedSize+1))
		outputCloseErr := output.Close()
		readerCloseErr := reader.Close()
		if copyErr != nil || outputCloseErr != nil || readerCloseErr != nil || written != expectedSize {
			return errors.New(options.extractionError)
		}
	}
	return nil
}

func unsafePortableZipPath(path string) bool {
	for _, component := range strings.FieldsFunc(path, func(character rune) bool {
		return character == '/' || character == '\\'
	}) {
		if component == "" || strings.TrimRight(component, " .") != component ||
			strings.ContainsAny(component, `<>:"|?*`) || strings.ContainsRune(component, '\x00') ||
			strings.ContainsFunc(component, unicode.IsControl) {
			return true
		}
		name := strings.ToUpper(component)
		if extension := strings.IndexByte(name, '.'); extension >= 0 {
			name = name[:extension]
		}
		if name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" ||
			name == "CONIN$" || name == "CONOUT$" || name == "CLOCK$" ||
			(len(name) == 4 && ((strings.HasPrefix(name, "COM") || strings.HasPrefix(name, "LPT")) &&
				name[3] >= '1' && name[3] <= '9')) {
			return true
		}
	}
	return false
}
