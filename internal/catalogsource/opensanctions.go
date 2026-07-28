package catalogsource

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type openSanctionsIndex struct {
	Name       string                          `json:"name"`
	Title      string                          `json:"title"`
	Version    string                          `json:"version"`
	LastExport string                          `json:"last_export"`
	Resources  []openSanctionsIndexResource    `json:"resources"`
	Dataset    *openSanctionsIndexDatasetBlock `json:"dataset,omitempty"`
}

type openSanctionsIndexDatasetBlock struct {
	Name       string                       `json:"name"`
	Title      string                       `json:"title"`
	Version    string                       `json:"version"`
	LastExport string                       `json:"last_export"`
	Resources  []openSanctionsIndexResource `json:"resources"`
}

type openSanctionsIndexResource struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Path      string `json:"path"`
	MimeType  string `json:"mime_type"`
	MediaType string `json:"media_type"`
	Size      int64  `json:"size"`
	SHA1      string `json:"sha1"`
	SHA256    string `json:"sha256"`
	Checksum  string `json:"checksum"`
}

func ParseOpenSanctionsIndex(data []byte, metadataURL, requestedDataset, resourceName string) (OpenSanctionsResource, error) {
	var index openSanctionsIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return OpenSanctionsResource{}, fmt.Errorf("%w: decode OpenSanctions index: %v", ErrInvalidSource, err)
	}
	name, title, version, lastExport, resources := index.Name, index.Title, index.Version, index.LastExport, index.Resources
	if index.Dataset != nil {
		name, title, version, lastExport, resources = index.Dataset.Name, index.Dataset.Title, index.Dataset.Version, index.Dataset.LastExport, index.Dataset.Resources
	}
	if name == "" {
		name = requestedDataset
	}
	if requestedDataset != "" && name != requestedDataset {
		return OpenSanctionsResource{}, fmt.Errorf("%w: metadata dataset %q does not match requested %q", ErrInvalidSource, name, requestedDataset)
	}
	for _, resource := range resources {
		if resource.Name != resourceName && resource.Path != resourceName {
			continue
		}
		rawURL := firstNonEmpty(resource.URL, resource.Path)
		if rawURL == "" {
			rawURL = "https://data.opensanctions.org/datasets/latest/" + name + "/" + resourceName
		} else if parsed, err := url.Parse(rawURL); err == nil && !parsed.IsAbs() {
			base, baseErr := url.Parse(metadataURL)
			if baseErr != nil {
				return OpenSanctionsResource{}, fmt.Errorf("%w: invalid metadata URL", ErrInvalidSource)
			}
			rawURL = base.ResolveReference(parsed).String()
		}
		algorithm, checksum := "", ""
		switch {
		case strings.TrimSpace(resource.SHA256) != "":
			algorithm, checksum = "sha256", resource.SHA256
		case strings.TrimSpace(resource.SHA1) != "":
			algorithm, checksum = "sha1", resource.SHA1
		case strings.HasPrefix(strings.ToLower(resource.Checksum), "sha256:"):
			algorithm, checksum = "sha256", strings.TrimSpace(strings.SplitN(resource.Checksum, ":", 2)[1])
		case strings.HasPrefix(strings.ToLower(resource.Checksum), "sha1:"):
			algorithm, checksum = "sha1", strings.TrimSpace(strings.SplitN(resource.Checksum, ":", 2)[1])
		}
		return OpenSanctionsResource{DatasetID: name, DatasetTitle: title, Version: version, LastExport: lastExport, ResourceName: resourceName, ResourceURL: rawURL, MediaType: firstNonEmpty(resource.MimeType, resource.MediaType, "application/x-ndjson"), Size: resource.Size, ChecksumAlgorithm: algorithm, Checksum: strings.ToLower(strings.TrimSpace(checksum))}, nil
	}
	return OpenSanctionsResource{}, fmt.Errorf("%w: resource %q not found", ErrInvalidSource, resourceName)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
