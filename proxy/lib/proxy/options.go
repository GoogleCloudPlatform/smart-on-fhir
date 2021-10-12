// Copyright 2020 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"fmt"
	"os"
	"strings"

	"bitbucket.org/creachadair/stringset" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/osenv" /* copybara-comment: osenv */

	glog "github.com/golang/glog" /* copybara-comment */
)

// Options of the reverse proxy server
type Options struct {
	// FhirIssuer : the "iss" claim expected in the SMARTonFHIR token.
	FhirIssuer string

	// Audience : a string that represents the expected audience for the access
	// token. It may be set to the same string as the Token Issuer's client ID
	// depending on how the Token Issuer populates the claim.
	Audience string

	// FhirIssuerClientID : the Relying Party client ID for the proxy as allocated by
	// the token issuer IDP. This may be used when the proxy calls OIDC
	// endpoints.
	FhirIssuerClientID string

	// FhirIssuerClientSecret : the Relying Party client secret for the proxy as
	// allocated by the token issuer IDP. This may be used when the proxy calls
	// OIDC endpoints.
	FhirIssuerClientSecret string

	// ProxyTo : the FHIR service root URL.
	ProxyTo string

	// ServiceAccountName : the service account name for the proxy to use when calling
	// the FHIR (PROXY_TO) endpoints.
	ServiceAccountName string

	// AllowedPathPrefix : a set of Healthcare API paths to
	// proxy. This provides the ability to limit which projects, datasets etc.
	// with which the proxy may be used.
	AllowedPathPrefix []string

	// ClientsOfProxy : a set of key/value pairs of client applications that
	// are able to access the proxy. When non-empty, all clients of this proxy
	// must pass in X-Client-ID and X-Client-Secret headers with their requests
	// and match one of the entries on this list, or else the request will be
	// unauthorized.
	ClientsOfProxy map[string]string

	// RemoveScopes : a set of scopes to remove from the
	// X-Authorization-Scope header that the proxy includes in its requests
	// to downstream servers.
	RemoveScopes stringset.Set

	// UseUserinfoToVerifyAccessToken : access token to the proxy maybe opaque
	// token but it can still validate with oidc userinfo endpoint
	UseUserinfoToVerifyAccessToken bool

	// WellKnownAuthorizationEndpoint : url to authorize for access token, published to /.well-known/smart-configuration
	WellKnownAuthorizationEndpoint string
	// WellKnownTokenEndpoint : url to exchange token using auth code or refresh token for access token, published to /.well-known/smart-configuration
	WellKnownTokenEndpoint string
	// WellKnownCapabilities : capabilities of the smart application, published to /.well-known/smart-configuration
	WellKnownCapabilities []string

	// USE_SECRET_MANAGER : use GCP SecretManager to store client secret and issuer secret.
	UseSecretManager bool
}

// ReadOptionsFromEnv reads options from env var
func ReadOptionsFromEnv() *Options {
	// FHIR_ISSUER: the "iss" claim expected in the SMARTonFHIR token.
	// Example: FHIR_ISSUER: "https://personas-staging-dot-hcls-data-connect-demo.appspot.com/oidc"
	fhirIssuer := osenv.MustVar("FHIR_ISSUER")

	// AUDIENCE: a string that represents the expected audience for the access
	// token. It may be set to the same string as the Token Issuer's client ID
	// depending on how the Token Issuer populates the claim.
	// Example: AUDIENCE: "https://fhirproxy-staging-dot-hcls-data-connect-demo.appspot.com"
	audience := osenv.MustVar("AUDIENCE")

	// FHIR_ISSUER_CLIENT_ID: the Relying Party client ID for the proxy as allocated by
	// the token issuer IDP. This may be used when the proxy calls OIDC
	// endpoints.
	// Example: FHIR_ISSUER_CLIENT_ID: "abcdefg1234567"
	fhirIssuerClientID := os.Getenv("FHIR_ISSUER_CLIENT_ID")

	// FHIR_ISSUER_CLIENT_SECRET: the Relying Party client secret for the proxy as
	// allocated by the token issuer IDP. This may be used when the proxy calls
	// OIDC endpoints.
	// Example: FHIR_ISSUER_CLIENT_SECRET: "0000-000-000000-00"
	fhirIssuerClientSecret := os.Getenv("FHIR_ISSUER_CLIENT_SECRET")

	// PROXY_TO: the FHIR service root URL.
	// Example: PROXY_TO: "https://healthcare.googleapis.com"
	proxyTo := osenv.MustVar("PROXY_TO")

	// SERVICE_ACCOUNT_NAME: the service account name for the proxy to use when calling
	// the FHIR (PROXY_TO) endpoints. Default is "fhirproxy".
	// Example: SERVICE_ACCOUNT_NAME: "fhirproxy"
	serviceAccountName := osenv.VarWithDefault("SERVICE_ACCOUNT_NAME", "fhirproxy")

	// ALLOWED_PATH_PREFIX: a comma-delimited set of Healthcare API paths to
	// proxy. This provides the ability to limit which projects, datasets etc.
	// with which the proxy may be used.
	// Example: ALLOWED_PATH_PREFIX: "/v1/projects/gcp-project/locations/us-central1/datasets/a"
	allowedPathPrefix := splitValuesByCommas(osenv.MustVar("ALLOWED_PATH_PREFIX"))
	if err := validateAllowedPathPrefix(allowedPathPrefix); err != nil {
		glog.Exitf("Invalid ALLOWED_PATH_PREFIX %v", err)
	}

	// CLIENTS_OF_PROXY: a set of key/value pairs of client applications that
	// are able to access the proxy. When non-empty, all clients of this proxy
	// must pass in X-Client-ID and X-Client-Secret headers with their requests
	// and match one of the entries on this list, or else the request will be
	// unauthorized.
	// Example: CLIENTS_OF_PROXY: "client_1=secret_1;client_2=secret_2"
	clientsOfProxy, err := parseClientsOfProxy(os.Getenv("CLIENTS_OF_PROXY"))
	if err != nil {
		glog.Exitf("Invalid CLIENTS_OF_PROXY %v", err)
	}

	// REMOVE_SCOPES: a comma-delimited set of scopes to remove from the
	// X-Authorization-Scope header that the proxy includes in its requests
	// to downstream servers.
	// Example: REMOVE_SCOPES: "openid,profile,email"
	removeScopes := splitValuesByCommas(osenv.MustVar("REMOVE_SCOPES"))

	useUserinfoToVerifyAccessToken := os.Getenv("USE_USERINFO_TO_VERIFY_ACCESSTOKEN") == "true"

	// WELL_KNOWN_AUTHORIZATION_ENDPOINT: url to authorize for access token
	// example: https://example.com/authoriize
	wellKnownAuthorizationEndpoint := osenv.MustVar("WELL_KNOWN_AUTHORIZATION_ENDPOINT")
	// WELL_KNOWN_TOKEN_ENDPOINT: url to exchange token using auth code or refresh token for access token
	// example: https://example.com/token
	wellKnownTokenEndpoint := osenv.MustVar("WELL_KNOWN_TOKEN_ENDPOINT")
	// WELL_KNOWN_CAPABILITIES: a comma-delimited set of capabilities,
	// see https://hl7.org/fhir/smart-app-launch/conformance/index.html#capability-sets
	wellKnownCapabilities := splitValuesByCommas(osenv.MustVar("WELL_KNOWN_CAPABILITIES"))

	// USE_SECRET_MANAGER : use GCP SecretManager to store client secret and issuer secret.
	useSecretManager := os.Getenv("USE_SECRET_MANAGER") == "true"

	return &Options{
		FhirIssuer:                     fhirIssuer,
		Audience:                       audience,
		FhirIssuerClientID:             fhirIssuerClientID,
		FhirIssuerClientSecret:         fhirIssuerClientSecret,
		ProxyTo:                        proxyTo,
		ServiceAccountName:             serviceAccountName,
		AllowedPathPrefix:              allowedPathPrefix,
		ClientsOfProxy:                 clientsOfProxy,
		RemoveScopes:                   stringset.New(removeScopes...),
		UseUserinfoToVerifyAccessToken: useUserinfoToVerifyAccessToken,
		UseSecretManager:               useSecretManager,
		WellKnownAuthorizationEndpoint: wellKnownAuthorizationEndpoint,
		WellKnownTokenEndpoint:         wellKnownTokenEndpoint,
		WellKnownCapabilities:          wellKnownCapabilities,
	}
}

func splitValuesByCommas(str string) []string {
	if len(str) == 0 {
		return nil
	}

	var res []string
	for _, s := range strings.Split(str, ",") {
		trimmed := strings.TrimSpace(s)
		if len(trimmed) > 0 {
			res = append(res, trimmed)
		}
	}

	return res
}

func validateAllowedPathPrefix(ss []string) error {
	for _, s := range ss {
		if !strings.HasPrefix(s, "/") {
			return fmt.Errorf("must begin with '/': %q", s)
		}
	}
	return nil
}

func parseClientsOfProxy(str string) (map[string]string, error) {
	res := map[string]string{}
	for _, c := range strings.Split(str, ";") {
		trimed := strings.TrimSpace(c)
		if len(trimed) == 0 {
			continue
		}

		ss := strings.Split(trimed, "=")
		if len(ss) != 2 {
			return nil, fmt.Errorf("client id and secret in incorrect format: %s", trimed)
		}

		clientID := strings.TrimSpace(ss[0])
		clientSecret := strings.TrimSpace(ss[1])

		res[clientID] = clientSecret
	}

	return res, nil
}
