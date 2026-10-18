// Package spec embeds the OpenAPI description of the briqyard API.
package spec

import _ "embed"

// OpenAPI is api/openapi.yaml.
//
//go:embed openapi.yaml
var OpenAPI []byte
