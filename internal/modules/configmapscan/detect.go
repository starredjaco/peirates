package configmapscan

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"regexp"
	"strings"
)

type match struct {
	kind       string
	confidence string
}

var (
	jwtCandidate     = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	awsID            = regexp.MustCompile(`(?:^|[^A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?:$|[^A-Z0-9])`)
	gcpAccessToken   = regexp.MustCompile(`(?:^|[^A-Za-z0-9._~-])ya29\.[A-Za-z0-9._~-]{10,}(?:$|[^A-Za-z0-9._~-])`)
	azureSAS         = regexp.MustCompile(`(?i)(?:^|[?&])sv=[^&\s]+(?:&[^\s]*?)?&sig=[^&\s]+|(?:^|[?&])sig=[^&\s]+(?:&[^\s]*?)?&sv=[^&\s]+`)
	azureAccountName = regexp.MustCompile(`(?i)(?:^|;)\s*AccountName\s*=\s*[^;\s]+`)
	azureAccountKey  = regexp.MustCompile(`(?i)(?:^|;)\s*AccountKey\s*=\s*[^;\s]+`)
	azureSharedSAS   = regexp.MustCompile(`(?i)(?:^|;)\s*SharedAccessSignature\s*=\s*[^;\s]+`)
)

func detect(data []byte) []match {
	value := string(data)
	found := make(map[string]string)
	for _, bounds := range jwtCandidate.FindAllStringIndex(value, -1) {
		if bounds[0] > 0 && isJWTSegmentByte(value[bounds[0]-1]) || bounds[1] < len(value) && isJWTSegmentByte(value[bounds[1]]) {
			continue
		}
		candidate := value[bounds[0]:bounds[1]]
		parts := strings.Split(candidate, ".")
		if len(parts) != 3 {
			continue
		}
		header, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil || !validJSONObject(header) {
			continue
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil || !validJSONObject(payload) {
			continue
		}
		if _, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
			continue
		}
		found["JWT-shaped token"] = "high"
		break
	}
	if hasPrivateKeyBlock(data) {
		found["private key block"] = "high"
	}
	if awsID.MatchString(value) {
		found["AWS access key ID"] = "medium"
	}
	if gcpAccessToken.MatchString(value) {
		found["Google OAuth access token candidate"] = "medium"
	}
	if azureSAS.MatchString(value) || (azureAccountName.MatchString(value) && (azureAccountKey.MatchString(value) || azureSharedSAS.MatchString(value))) {
		found["Azure Storage credential candidate"] = "medium"
	}
	var object map[string]any
	if json.Unmarshal(data, &object) == nil {
		if equalString(object, "type", "service_account") && nonEmptyString(object, "client_email") && nonEmptyString(object, "private_key") {
			found["Google service account key"] = "high"
		}
		if hasAnyString(object, "tenantId", "tenant_id", "AZURE_TENANT_ID") && hasAnyString(object, "clientId", "client_id", "AZURE_CLIENT_ID") && hasAnyString(object, "clientSecret", "client_secret", "AZURE_CLIENT_SECRET") {
			found["Azure client secret settings"] = "high"
		}
	}
	ordered := []string{"JWT-shaped token", "private key block", "AWS access key ID", "Google OAuth access token candidate", "Google service account key", "Azure Storage credential candidate", "Azure client secret settings"}
	var matches []match
	for _, kind := range ordered {
		if confidence, ok := found[kind]; ok {
			matches = append(matches, match{kind: kind, confidence: confidence})
		}
	}
	return matches
}

func isJWTSegmentByte(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '_' || value == '-' || value == '.'
}

func hasPrivateKeyBlock(data []byte) bool {
	for remaining := string(data); ; {
		index := strings.Index(remaining, "-----BEGIN ")
		if index < 0 {
			return false
		}
		remaining = remaining[index:]
		if block, _ := pem.Decode([]byte(remaining)); block != nil {
			switch block.Type {
			case "PRIVATE KEY", "OPENSSH PRIVATE KEY", "RSA PRIVATE KEY", "DSA PRIVATE KEY", "EC PRIVATE KEY", "ED25519 PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
				return true
			}
		}
		remaining = remaining[len("-----BEGIN "):]
	}
}

func validJSONObject(data []byte) bool {
	var value map[string]any
	return json.Unmarshal(data, &value) == nil && value != nil
}

func equalString(object map[string]any, key, expected string) bool {
	value, ok := object[key].(string)
	return ok && value == expected
}

func nonEmptyString(object map[string]any, key string) bool {
	value, ok := object[key].(string)
	return ok && strings.TrimSpace(value) != ""
}

func hasAnyString(object map[string]any, keys ...string) bool {
	for _, key := range keys {
		if nonEmptyString(object, key) {
			return true
		}
	}
	return false
}
