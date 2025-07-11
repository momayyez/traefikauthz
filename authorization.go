package traefikauthz

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type errorResponse struct {
	IsSuccess  bool   `json:"isSuccess"`
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message"`
}

// writeJSONError sends a JSON formatted error to the client
func writeJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	resp := errorResponse{
		IsSuccess:  false,
		StatusCode: statusCode,
		Message:    message,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// Config holds the plugin configuration
type Config struct {
	KeycloakURL           string            `json:"keycloakURL,omitempty"`
	KeycloakClientId      string            `json:"keycloakClientId,omitempty"`
	ResourceSegmentIndex  int               `json:"resourceSegmentIndex,omitempty"`
	ScopeSegmentIndex     int               `json:"scopeSegmentIndex,omitempty"`
	LogLevel              string            `json:"logLevel,omitempty"` // "off", "info", "debug"
	StaticPermissions     map[string]string `json:"staticPermissions,omitempty"` // prefix path -> permission
}

// CreateConfig returns a config with default values
func CreateConfig() *Config {
	return &Config{
		ResourceSegmentIndex: 3,
		ScopeSegmentIndex:    4,
		LogLevel:             "info",
		StaticPermissions:    make(map[string]string),
	}
}

// AuthMiddleware holds the plugin runtime state
type AuthMiddleware struct {
	next                 http.Handler
	keycloakClientId     string
	keycloakUrl          string
	name                 string
	resourceSegmentIndex int
	scopeSegmentIndex    int
	logLevel             string
	staticPermissions    map[string]string
}

// ServeHTTP is the core authorization logic
func (am *AuthMiddleware) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if am.logLevel == "debug" {
		fmt.Println("🔎 [AUTH] ServeHTTP Called")
	}

	authorizationHeader := req.Header.Get("Authorization")
	if authorizationHeader == "" {
		if am.logLevel != "off" {
			fmt.Println("❌ [AUTH] Authorization header is missing")
		}
		writeJSONError(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	var permission string
	matched := false

	// Match static permission from config (based on prefix)
	for prefix, staticPerm := range am.staticPermissions {
		if strings.HasPrefix(req.URL.Path, prefix) {
			permission = staticPerm
			matched = true
			if am.logLevel == "debug" {
				fmt.Printf("📌 [AUTH] Static permission matched (prefix) for path [%s] → %s\n", req.URL.Path, permission)
			}
			break
		}
	}

	// If no static match, build dynamic permission
	if !matched {
		pathParts := strings.Split(req.URL.Path, "/")
		if len(pathParts) <= am.scopeSegmentIndex {
			if am.logLevel != "off" {
				fmt.Println("❌ [AUTH] Path too short for configured resource/scope indexes.")
			}
			writeJSONError(w, "Invalid path format. Expected enough segments", http.StatusBadRequest)
			return
		}
		resource := strings.ToLower(pathParts[am.resourceSegmentIndex])
		scope := strings.ToLower(pathParts[am.scopeSegmentIndex])
		permission = resource + "#" + scope

		if am.logLevel == "debug" {
			fmt.Println("🔎 [AUTH] Derived permission:", permission)
		}
	}

	formData := url.Values{}
	formData.Set("permission", permission)
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	formData.Set("audience", am.keycloakClientId)

	if am.keycloakUrl == "" {
		if am.logLevel != "off" {
			fmt.Println("❌ [CONFIG] Keycloak URL is empty in middleware. Cannot proceed.")
		}
		writeJSONError(w, "Misconfigured Keycloak URL", http.StatusInternalServerError)
		return
	}

	if am.logLevel == "debug" {
		fmt.Println("🔄 [REQUEST] Sending request to Keycloak:", am.keycloakUrl)
		fmt.Println("🔸 [DEBUG] Authorization Header:", authorizationHeader)
	}

	kcReq, err := http.NewRequest("POST", am.keycloakUrl, strings.NewReader(formData.Encode()))
	if err != nil {
		if am.logLevel != "off" {
			fmt.Println("❌ [HTTP] Error creating Keycloak request:", err)
		}
		writeJSONError(w, "Failed to create request to Keycloak", http.StatusInternalServerError)
		return
	}
	kcReq.Header.Set("Authorization", authorizationHeader)
	kcReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	kcResp, err := client.Do(kcReq)
	if err != nil {
		if am.logLevel != "off" {
			fmt.Println("❌ [HTTP] Error performing Keycloak request:", err)
		}
		writeJSONError(w, "Unable to reach Keycloak", http.StatusBadGateway)
		return
	}
	defer kcResp.Body.Close()

	bodyBytes, _ := io.ReadAll(kcResp.Body)
	bodyString := string(bodyBytes)

	if am.logLevel == "debug" {
		fmt.Println("🔎 [HTTP] Keycloak response status:", kcResp.Status)
		fmt.Println("📦 [HTTP] Keycloak response body:", bodyString)
	} else if am.logLevel == "info" {
		fmt.Println("🔎 [HTTP] Keycloak response status:", kcResp.Status)
	}

	// Override 400 to 403 for specific Keycloak errors
	if kcResp.StatusCode == http.StatusBadRequest &&
		(strings.Contains(bodyString, `"error":"invalid_scope"`) || strings.Contains(bodyString, `"error":"invalid_resource"`)) {
		if am.logLevel != "off" {
			fmt.Println("🚫 [AUTHZ] Keycloak returned 400 with invalid scope/resource – overriding to 403")
		}
		writeJSONError(w, "Access denied", http.StatusForbidden)
		return
	}

	// Pass request if authorized
	if kcResp.StatusCode == http.StatusOK {
		if am.logLevel != "off" {
			fmt.Println("✅ [AUTHZ] Access granted by Keycloak")
		}
		am.next.ServeHTTP(w, req)
	} else {
		if am.logLevel != "off" {
			fmt.Printf("❌ [AUTHZ] Access denied by Keycloak. Status code: %d\n", kcResp.StatusCode)
		}
		writeJSONError(w, "Access denied", kcResp.StatusCode)
	}
}

// New initializes the middleware instance
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if strings.ToLower(config.LogLevel) != "off" {
		fmt.Println("🔧 [INIT] New Middleware Initialization")
		fmt.Printf("🔧 [CONFIG] Raw config: %+v\n", config)
	}

	if config == nil {
		if strings.ToLower(config.LogLevel) != "off" {
			fmt.Println("❌ [CONFIG] Received nil config! Middleware cannot proceed.")
		}
		return nil, fmt.Errorf("nil config provided")
	}
	if strings.TrimSpace(config.KeycloakURL) == "" && strings.ToLower(config.LogLevel) != "off" {
		fmt.Println("⚠️  [CONFIG] KeycloakURL is empty!")
	}
	if strings.TrimSpace(config.KeycloakClientId) == "" && strings.ToLower(config.LogLevel) != "off" {
		fmt.Println("⚠️  [CONFIG] KeycloakClientId is empty!")
	}

	mw := &AuthMiddleware{
		next:                 next,
		name:                 name,
		keycloakUrl:          config.KeycloakURL,
		keycloakClientId:     config.KeycloakClientId,
		resourceSegmentIndex: config.ResourceSegmentIndex,
		scopeSegmentIndex:    config.ScopeSegmentIndex,
		logLevel:             strings.ToLower(config.LogLevel),
		staticPermissions:    config.StaticPermissions,
	}

	if mw.logLevel != "off" {
		fmt.Printf("🔧 [INIT] Middleware initialized with keycloakUrl: [%s], keycloakClientId: [%s]\n", mw.keycloakUrl, mw.keycloakClientId)
	}

	return mw, nil
}
