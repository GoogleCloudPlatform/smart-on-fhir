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
	"os"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"bitbucket.org/creachadair/stringset" /* copybara-comment */
)

func TestReadOptionsFromEnv(t *testing.T) {
	tests := []struct {
		name  string
		input map[string]string
		want  *Options
	}{
		{
			name: "mini",
			input: map[string]string{
				"FHIR_ISSUER":                       "https://example.com/issuer",
				"AUDIENCE":                          "aud",
				"PROXY_TO":                          "https://example.com/fhir",
				"ALLOWED_PATH_PREFIX":               "/a,/b",
				"REMOVE_SCOPES":                     "openid,offline",
				"WELL_KNOWN_AUTHORIZATION_ENDPOINT": "https://example.com/issuer/auth",
				"WELL_KNOWN_TOKEN_ENDPOINT":         "https://example.com/issuer/token",
				"WELL_KNOWN_CAPABILITIES":           "launch-ehr,launch-standalone",
			},
			want: &Options{
				FhirIssuer:                     "https://example.com/issuer",
				Audience:                       "aud",
				ProxyTo:                        "https://example.com/fhir",
				ServiceAccountName:             "fhirproxy",
				AllowedPathPrefix:              []string{"/a", "/b"},
				ClientsOfProxy:                 map[string]string{},
				RemoveScopes:                   stringset.New("openid", "offline"),
				WellKnownAuthorizationEndpoint: "https://example.com/issuer/auth",
				WellKnownTokenEndpoint:         "https://example.com/issuer/token",
				WellKnownCapabilities:          []string{"launch-ehr", "launch-standalone"},
			},
		},
		{
			name: "all",
			input: map[string]string{
				"FHIR_ISSUER":                        "https://example.com/issuer",
				"AUDIENCE":                           "aud",
				"FHIR_ISSUER_CLIENT_ID":              "client_id",
				"FHIR_ISSUER_CLIENT_SECRET":          "client_secret",
				"PROXY_TO":                           "https://example.com/fhir",
				"SERVICE_ACCOUNT_NAME":               "sa-name",
				"ALLOWED_PATH_PREFIX":                "/a,/b",
				"CLIENTS_OF_PROXY":                   "c1=s1;c2=s2;",
				"REMOVE_SCOPES":                      "openid,offline",
				"USE_USERINFO_TO_VERIFY_ACCESSTOKEN": "true",
				"WELL_KNOWN_AUTHORIZATION_ENDPOINT":  "https://example.com/issuer/auth",
				"WELL_KNOWN_TOKEN_ENDPOINT":          "https://example.com/issuer/token",
				"WELL_KNOWN_CAPABILITIES":            "launch-ehr,launch-standalone",
				"USE_SECRET_MANAGER":                 "true",
			},
			want: &Options{
				FhirIssuer:                     "https://example.com/issuer",
				Audience:                       "aud",
				FhirIssuerClientID:             "client_id",
				FhirIssuerClientSecret:         "client_secret",
				ProxyTo:                        "https://example.com/fhir",
				ServiceAccountName:             "sa-name",
				AllowedPathPrefix:              []string{"/a", "/b"},
				ClientsOfProxy:                 map[string]string{"c1": "s1", "c2": "s2"},
				RemoveScopes:                   stringset.New("openid", "offline"),
				UseUserinfoToVerifyAccessToken: true,
				WellKnownAuthorizationEndpoint: "https://example.com/issuer/auth",
				WellKnownTokenEndpoint:         "https://example.com/issuer/token",
				WellKnownCapabilities:          []string{"launch-ehr", "launch-standalone"},
				UseSecretManager:               true,
			},
		},
		{
			name: "trim spaces",
			input: map[string]string{
				"FHIR_ISSUER":                       "https://example.com/issuer",
				"AUDIENCE":                          "aud",
				"FHIR_ISSUER_CLIENT_ID":             "client_id",
				"FHIR_ISSUER_CLIENT_SECRET":         "client_secret",
				"PROXY_TO":                          "https://example.com/fhir",
				"SERVICE_ACCOUNT_NAME":              "sa-name",
				"ALLOWED_PATH_PREFIX":               " /a , /b ",
				"CLIENTS_OF_PROXY":                  " c1 = s1 ; c2 = s2 ; ",
				"REMOVE_SCOPES":                     "openid , offline",
				"WELL_KNOWN_AUTHORIZATION_ENDPOINT": "https://example.com/issuer/auth",
				"WELL_KNOWN_TOKEN_ENDPOINT":         "https://example.com/issuer/token",
				"WELL_KNOWN_CAPABILITIES":           "launch-ehr, launch-standalone",
			},
			want: &Options{
				FhirIssuer:                     "https://example.com/issuer",
				Audience:                       "aud",
				FhirIssuerClientID:             "client_id",
				FhirIssuerClientSecret:         "client_secret",
				ProxyTo:                        "https://example.com/fhir",
				ServiceAccountName:             "sa-name",
				AllowedPathPrefix:              []string{"/a", "/b"},
				ClientsOfProxy:                 map[string]string{"c1": "s1", "c2": "s2"},
				RemoveScopes:                   stringset.New("openid", "offline"),
				WellKnownAuthorizationEndpoint: "https://example.com/issuer/auth",
				WellKnownTokenEndpoint:         "https://example.com/issuer/token",
				WellKnownCapabilities:          []string{"launch-ehr", "launch-standalone"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic %v", r)
				}
			}()
			setupEnvs(t, tc.input)
			got := ReadOptionsFromEnv()
			if d := cmp.Diff(tc.want, got); len(d) > 0 {
				t.Errorf("Options (-want, +got): %s", d)
			}
		})
	}
}

func setupEnvs(t *testing.T, m map[string]string) {
	t.Helper()

	for k, v := range m {
		os.Setenv(k, v)
	}
	t.Cleanup(func() {
		for k := range m {
			os.Unsetenv(k)
		}
	})
}
