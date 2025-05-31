package traefikauthz

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Config holds the plugin configuration (camelCase names to match YAML keys)
type Config struct {
	KeycloakURL           string `json:"keycloakURL,omitempty"`
	KeycloakClientId      string `json:"keycloakClientId,omitempty"`
	ResourceSegmentIndex  int    `json:"resourceSegmentIndex,omitempty"`
	ScopeSegmentIndex     int    `json:"scopeSegmentIndex,omitempty"`
	LogLevel              string `json:"logLevel,omitempty"` // "off", "info", "debug"
}

// CreateConfig creates an empty config; actual values come from YAML
func CreateConfig() *Config {
	return &Config{
		ResourceSegmentIndex: 3,
		ScopeSegmentIndex:    4,
		LogLevel:             "info",
	}
}

// AuthMiddleware holds the plugin state
type AuthMiddleware struct {
	next                 http.Handler
	keycloakClientId     string
	keycloakUrl          string
	name                 string
	resourceSegmentIndex int
	scopeSegmentIndex    int
	logLevel             string
}

// ServeHTTP handles the incoming request and checks permission via Keycloak
func (am *AuthMiddleware) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if am.logLevel == "debug" {
		fmt.Println("🔎 [AUTH] ServeHTTP Called")
	}

	authorizationHeader := req.Header.Get("Authorization")
	if authorizationHeader == "" {
		if am.logLevel != "off" {
			fmt.Println("❌ [AUTH] Authorization header is missing")
		}
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	// 🧠 Extract the path and derive `resource` and `scope`
	pathParts := strings.Split(req.URL.Path, "/")
	if len(pathParts) <= am.scopeSegmentIndex {
		if am.logLevel != "off" {
			fmt.Println("❌ [AUTH] Path too short for configured resource/scope indexes.")
		}
		http.Error(w, "Invalid path format. Expected enough segments", http.StatusBadRequest)
		return
	}

	resource := strings.ToLower(pathParts[am.resourceSegmentIndex])
	scope := strings.ToLower(pathParts[am.scopeSegmentIndex])
	permission := resource + "#" + scope

	if am.logLevel == "debug" {
		fmt.Println("🔎 [AUTH] Derived permission:", permission)
	}

	formData := url.Values{}
	formData.Set("permission", permission)
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	formData.Set("audience", am.keycloakClientId)

	if am.keycloakUrl == "" {
		if am.logLevel != "off" {
			fmt.Println("❌ [CONFIG] Keycloak URL is empty in middleware. Cannot proceed.")
		}
		http.Error(w, "Misconfigured Keycloak URL", http.StatusInternalServerError)
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
		http.Error(w, err.Error(), http.StatusUnauthorized)
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
		http.Error(w, err.Error(), http.StatusUnauthorized)
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

	if kcResp.StatusCode == http.StatusOK {
		if am.logLevel != "off" {
			fmt.Println("✅ [AUTHZ] Access granted by Keycloak")
		}
		am.next.ServeHTTP(w, req)
	} else {
		if am.logLevel != "off" {
			fmt.Printf("❌ [AUTHZ] Access denied by Keycloak. Status code: %d\n", kcResp.StatusCode)
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

// New is called by Traefik to create the middleware instance
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
	}

	if mw.logLevel != "off" {
		fmt.Printf("🔧 [INIT] Middleware initialized with keycloakUrl: [%s], keycloakClientId: [%s]\n", mw.keycloakUrl, mw.keycloakClientId)
	}

	return mw, nil
}
