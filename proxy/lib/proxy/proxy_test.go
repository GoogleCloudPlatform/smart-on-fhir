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
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/googleapis/gax-go/v2" /* copybara-comment */
	"google3/third_party/golang/github_com/alicebob/miniredis/v/v2/miniredis"
	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"bitbucket.org/creachadair/stringset" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auth" /* copybara-comment: auth */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/cache" /* copybara-comment: cache */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/cache/rediz" /* copybara-comment: rediz */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeoidcissuer" /* copybara-comment: fakeoidcissuer */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	credentialspb "google.golang.org/genproto/googleapis/iam/credentials/v1" /* copybara-comment: common_go_proto */
)

const (
	enableCache  = true
	disableCache = false
)

var (
	cacheMaxExpiry = 10 * time.Minute
)

func TestWellKnownSmartConfigure(t *testing.T) {
	opts := &Options{
		FhirIssuer:                     issuerURL,
		Audience:                       issuerURL,
		AllowedPathPrefix:              []string{"/"},
		WellKnownAuthorizationEndpoint: "https://example.com/auth",
		WellKnownTokenEndpoint:         "https://example.com/token",
		WellKnownCapabilities:          []string{"launch-ehr", "launch-standalone"},
	}
	_, srv, _, _, _, _ := setup(t, opts, disableCache)

	r, err := http.NewRequest(http.MethodGet, srv.URL+"/.well-known/smart-configuration", nil)
	if err != nil {
		t.Fatalf("NewRequest() failed: %v", err)
	}
	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatalf("Do Request failed: %v", err)
	}

	got := &WellKnownSmartConfigureResponse{}
	if err := httputils.DecodeJSON(resp.Body, got); err != nil {
		t.Fatalf("DecodeJSON failed: %v", err)
	}

	want := &WellKnownSmartConfigureResponse{
		AuthorizationEndpoint: "https://example.com/auth",
		TokenEndpoint:         "https://example.com/token",
		Capabilities:          []string{"launch-ehr", "launch-standalone"},
	}

	if d := cmp.Diff(want, got); len(d) > 0 {
		t.Errorf("/.well-known/smart-configuration response (-want, + got): %s", d)
	}
}

func TestFixProxyDirector(t *testing.T) {
	opts := &Options{FhirIssuer: issuerURL, Audience: issuerURL, AllowedPathPrefix: []string{"/"}}
	_, srv, fake, _, oidc, _ := setup(t, opts, disableCache)

	claims := simpleClaims("")

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	r, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest() failed: %v", err)
	}
	r.Header.Set("Connection", "close")
	r.Header.Set("Authorization", "bearer "+tok)
	r.Host = "example.com"

	r.Close = true

	fake.reset(t)
	fake.respContent = "ok-body"
	fake.respStatus = http.StatusOK

	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatalf("Do Request failed: %v", err)
	}

	u, err := url.Parse(opts.ProxyTo)
	if err != nil {
		t.Fatalf("url.Parse(%q) failed: %v", opts.ProxyTo, err)
	}

	wantHost := u.Host
	if fake.req.Host != wantHost {
		t.Errorf("r.Host = %q, wants %q", r.Host, wantHost)
	}

	wantXHost := r.Host
	if fake.req.Header.Get("X-Forwarded-Host") != wantXHost {
		t.Errorf("r.Header(X-Forwarded-Host) = %q, wants %q", fake.req.Header.Get("X-Forwarded-Host"), wantXHost)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d wants %d", resp.StatusCode, http.StatusOK)
	}
}

func TestProxy(t *testing.T) {
	_, srv, fake, _, oidc, _ := setup(t, &Options{FhirIssuer: issuerURL, Audience: issuerURL, AllowedPathPrefix: []string{"/"}}, disableCache)

	claims := simpleClaims("")

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	tests := []struct {
		name        string
		method      string
		host        string
		path        string
		query       string
		header      map[string]string
		body        string
		respStatus  int
		respContent string
		wantReq     *regexp.Regexp
		wantResp    *regexp.Regexp
	}{
		{
			name:        "simple",
			method:      http.MethodGet,
			host:        "example.com",
			path:        "/",
			respStatus:  http.StatusOK,
			respContent: "okbody",
			wantReq:     regexp.MustCompile(`(?s)GET /.*?X-Forwarded-Host: .*?`),
			wantResp:    regexp.MustCompile(`(?s).*?200 OK.*?okbody$`),
		},
		{
			name:        "empty path",
			method:      http.MethodGet,
			host:        "example.com",
			path:        "",
			respStatus:  http.StatusOK,
			respContent: "okbody",
			wantReq:     regexp.MustCompile(`(?s)GET /.*?X-Forwarded-Host: .*?`),
			wantResp:    regexp.MustCompile(`(?s).*?200 OK.*?okbody$`),
		},
		{
			name:        "with path and query",
			method:      http.MethodGet,
			host:        "example.com",
			path:        "/a",
			query:       "b=c&d=e",
			header:      map[string]string{"h1": "v1"},
			respStatus:  http.StatusBadRequest,
			respContent: "bad request",
			wantReq:     regexp.MustCompile(`(?s)GET /a\?b=c&d=e.*?`),
			wantResp:    regexp.MustCompile(`(?s).*?400 Bad Request.*?bad request$`),
		},
		{
			name:        "post request with body",
			method:      http.MethodPost,
			host:        "example.com",
			path:        "/a",
			query:       "b=c&d=e",
			header:      map[string]string{"h1": "v1"},
			body:        "postbody",
			respStatus:  http.StatusBadRequest,
			respContent: "bad request",
			wantReq:     regexp.MustCompile(`(?s)POST /a\?b=c&d=e.*?postbody$`),
			wantResp:    regexp.MustCompile(`(?s).*?400 Bad Request.*?bad request$`),
		},
		{
			name:        "X-Forwarded-For header, mock the proxy is behind proxy",
			method:      http.MethodGet,
			host:        "example.com",
			path:        "/a",
			header:      map[string]string{"X-Forwarded-For": "192.168.111.1, 192.168.111.2"},
			respStatus:  http.StatusOK,
			respContent: "okbody",
			wantReq:     regexp.MustCompile(`(?s)GET /a.*?X-Forwarded-For: 192\.168\.111\.1, 192\.168\.111\.2, .*`),
			wantResp:    regexp.MustCompile(`(?s).*?200 OK.*?okbody$`),
		},
		{
			name:        "call liveness endpoint does not goto proxy",
			method:      http.MethodGet,
			host:        "example.com",
			path:        "/liveness",
			respStatus:  http.StatusBadRequest,
			respContent: "bad request",
			wantReq:     regexp.MustCompile("^$"),
			wantResp:    regexp.MustCompile(`(?s).*?200 OK.*?liveness body$`),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target := srv.URL + tc.path
			if len(tc.query) > 0 {
				target += "?" + tc.query
			}

			r, err := http.NewRequest(tc.method, target, strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("NewRequest() failed: %v", err)
			}
			for h, v := range tc.header {
				r.Header.Set(h, v)
			}
			r.Header.Set("Connection", "close")
			r.Header.Set("Authorization", "bearer "+tok)
			r.Host = tc.host

			r.Close = true

			fake.reset(t)
			fake.respContent = tc.respContent
			fake.respStatus = tc.respStatus

			resp, err := srv.Client().Do(r)
			if err != nil {
				t.Fatalf("Do Request failed: %v", err)
			}

			gotReq := fake.reqStr

			if !tc.wantReq.MatchString(gotReq) {
				t.Errorf("reqStr %q does not match %q", gotReq, tc.wantReq.String())
			}

			gotResp := responseToString(t, resp)

			if !tc.wantResp.MatchString(gotResp) {
				t.Errorf("resp %q does not match %q", gotReq, tc.wantResp.String())
			}
		})
	}
}

func TestFhirHeader(t *testing.T) {
	tests := []struct {
		name        string
		opts        *Options
		header      map[string]string
		scope       string
		wantHeaders http.Header
	}{
		{
			name: "default",
			opts: &Options{FhirIssuer: issuerURL, Audience: issuerURL, AllowedPathPrefix: []string{"/"}},
			wantHeaders: http.Header{
				"Authorization":            {"Bearer this-is-a-token"},
				"X-Authorization-Issuer":   {"https://issuer.example.com"},
				"X-Authorization-Patient":  {"user-1"},
				"X-Authorization-Scope":    {"openid offline patient/*.read"},
				"X-Authorization-Subject":  {"sub"},
				"X-Authorization-Token-Id": {"token-id"},
				"X-Forwarded-Host":         {"example.com"},
				"X-Forwarded-Proto":        {"http"},
			},
		},
		{
			name: "filtered",
			opts: &Options{FhirIssuer: issuerURL, Audience: issuerURL, RemoveScopes: stringset.New("openid"), AllowedPathPrefix: []string{"/"}},
			wantHeaders: http.Header{
				"Authorization":            {"Bearer this-is-a-token"},
				"X-Authorization-Issuer":   {"https://issuer.example.com"},
				"X-Authorization-Patient":  {"user-1"},
				"X-Authorization-Scope":    {"offline patient/*.read"},
				"X-Authorization-Subject":  {"sub"},
				"X-Authorization-Token-Id": {"token-id"},
				"X-Forwarded-Host":         {"example.com"},
				"X-Forwarded-Proto":        {"http"},
			},
		},
		{
			name:   "keeps headers",
			opts:   &Options{FhirIssuer: issuerURL, Audience: issuerURL, AllowedPathPrefix: []string{"/"}},
			header: map[string]string{"Via": "b"},
			wantHeaders: http.Header{
				"Via":                      {"b"},
				"Authorization":            {"Bearer this-is-a-token"},
				"X-Authorization-Issuer":   {"https://issuer.example.com"},
				"X-Authorization-Patient":  {"user-1"},
				"X-Authorization-Scope":    {"openid offline patient/*.read"},
				"X-Authorization-Subject":  {"sub"},
				"X-Authorization-Token-Id": {"token-id"},
				"X-Forwarded-Host":         {"example.com"},
				"X-Forwarded-Proto":        {"http"},
			},
		},
		{
			name:   "remove X-Client-Secret headers",
			opts:   &Options{FhirIssuer: issuerURL, Audience: issuerURL, ClientsOfProxy: map[string]string{"id": "secret"}, AllowedPathPrefix: []string{"/"}},
			header: map[string]string{"X-Client-Id": "id", "X-Client-Secret": "secret"},
			wantHeaders: http.Header{
				"Authorization":            {"Bearer this-is-a-token"},
				"X-Authorization-Issuer":   {"https://issuer.example.com"},
				"X-Authorization-Patient":  {"user-1"},
				"X-Authorization-Scope":    {"openid offline patient/*.read"},
				"X-Authorization-Subject":  {"sub"},
				"X-Authorization-Token-Id": {"token-id"},
				"X-Client-Id":              {"id"},
				"X-Forwarded-Host":         {"example.com"},
				"X-Forwarded-Proto":        {"http"},
			},
		},
		{
			name:   "smart-on-fhir and consent scopes",
			opts:   &Options{FhirIssuer: issuerURL, Audience: issuerURL, ClientsOfProxy: map[string]string{"id": "secret"}, AllowedPathPrefix: []string{"/"}},
			header: map[string]string{"X-Client-Id": "id", "X-Client-Secret": "secret"},
			scope:  "consent/actor/Practitioner/123 observation/*.write purp/v3/TREAT env/app/X random_scope",
			wantHeaders: http.Header{
				"Authorization":            {"Bearer this-is-a-token"},
				"X-Authorization-Issuer":   {"https://issuer.example.com"},
				"X-Authorization-Patient":  {"user-1"},
				"X-Authorization-Scope":    {"observation/*.write random_scope"},
				"X-Authorization-Subject":  {"sub"},
				"X-Authorization-Token-Id": {"token-id"},
				"X-Client-Id":              {"id"},
				"X-Forwarded-Host":         {"example.com"},
				"X-Forwarded-Proto":        {"http"},
				"X-Consent-Scope":          {"consent/actor/Practitioner/123 purp/v3/TREAT env/app/X"},
			},
		},
		{
			name:   "only consent scopes",
			opts:   &Options{FhirIssuer: issuerURL, Audience: issuerURL, ClientsOfProxy: map[string]string{"id": "secret"}, AllowedPathPrefix: []string{"/"}},
			header: map[string]string{"X-Client-Id": "id", "X-Client-Secret": "secret"},
			scope:  "consent/actor/Practitioner/123 purp/v3/ETREAT",
			wantHeaders: http.Header{
				"Authorization":            {"Bearer this-is-a-token"},
				"X-Authorization-Token-Id": {"token-id"},
				"X-Client-Id":              {"id"},
				"X-Forwarded-Host":         {"example.com"},
				"X-Forwarded-Proto":        {"http"},
				"X-Consent-Scope":          {"consent/actor/Practitioner/123 purp/v3/ETREAT"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, srv, fake, iam, oidc, _ := setup(t, tc.opts, disableCache)
			iam.reset()

			claims := simpleClaims(tc.scope)
			tok, err := oidc.Sign(nil, claims)
			if err != nil {
				t.Fatalf("oidc.Sign() failed: %v", err)
			}

			r, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
			if err != nil {
				t.Fatalf("NewRequest() failed: %v", err)
			}
			for h, v := range tc.header {
				r.Header.Set(h, v)
			}
			r.Header.Set("Connection", "close")
			r.Header.Set("Authorization", "bearer "+tok)
			r.Host = "example.com"

			r.Close = true

			fake.reset(t)
			fake.respContent = "ok-body"
			fake.respStatus = http.StatusOK

			if _, err := srv.Client().Do(r); err != nil {
				t.Fatalf("Do Request failed: %v", err)
			}

			got := fake.req.Header.Clone()
			skipHeaders := []string{
				"Accept-Encoding",
				"User-Agent",
				"X-Forwarded-For",
			}

			for _, skip := range skipHeaders {
				got.Del(skip)
			}

			if d := cmp.Diff(tc.wantHeaders, got); len(d) > 0 {
				t.Errorf("headers to backend (-want, +got): %s", d)
			}
		})
	}
}

func TestProxy_AllowedPathPrefix(t *testing.T) {
	_, srv, fake, _, oidc, _ := setup(t, &Options{FhirIssuer: issuerURL, Audience: issuerURL, AllowedPathPrefix: []string{"/a"}}, disableCache)

	claims := simpleClaims("")

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	tests := []struct {
		name   string
		path   string
		status int
	}{
		{
			name:   "path allow",
			path:   "/a",
			status: http.StatusOK,
		},
		{
			name:   "path not allow",
			path:   "/b",
			status: http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, srv.URL+tc.path, nil)
			if err != nil {
				t.Fatalf("NewRequest() failed: %v", err)
			}
			r.Header.Set("Connection", "close")
			r.Header.Set("Authorization", "bearer "+tok)
			r.Host = "example.com"

			r.Close = true

			fake.reset(t)
			fake.respContent = "ok-body"
			fake.respStatus = http.StatusOK

			resp, err := srv.Client().Do(r)
			if err != nil {
				t.Fatalf("Do Request failed: %v", err)
			}

			if resp.StatusCode != tc.status {
				t.Errorf("status = %d wants %d", resp.StatusCode, tc.status)
			}
		})
	}
}

func TestProxyError_fetchAccessTokenFailed(t *testing.T) {
	s, srv, fake, iam, oidc, _ := setup(t, &Options{FhirIssuer: issuerURL, Audience: issuerURL, AllowedPathPrefix: []string{"/"}}, disableCache)
	s.gcpAccessToken = &accessToken{
		token:  "this-is-a-token",
		expire: time.Now().Add(-time.Hour),
	}

	claims := simpleClaims("")

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	r, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest() failed: %v", err)
	}
	r.Header.Set("Connection", "close")
	r.Header.Set("Authorization", "bearer "+tok)
	r.Host = "example.com"

	r.Close = true

	fake.reset(t)
	fake.respContent = "ok-body"
	fake.respStatus = http.StatusOK

	iam.respErr = true

	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatalf("Do Request failed: %v", err)
	}

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d wants %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestProxy_cacheGCPAccessToken(t *testing.T) {
	s, srv, fake, iam, oidc, _ := setup(t, &Options{FhirIssuer: issuerURL, Audience: issuerURL, AllowedPathPrefix: []string{"/"}}, disableCache)

	claims := simpleClaims("")

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	r, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest() failed: %v", err)
	}
	r.Header.Set("Connection", "close")
	r.Header.Set("Authorization", "bearer "+tok)
	r.Host = "example.com"

	r.Close = true

	fake.reset(t)
	fake.respContent = "ok-body"
	fake.respStatus = http.StatusOK

	cachedToken := "cached-token"

	tests := []struct {
		name               string
		tokenExpire        time.Time
		lastFetch          time.Time
		wantGenGCPTokenReq bool
	}{
		{
			name:               "has valid token",
			tokenExpire:        time.Now().Add(time.Hour),
			wantGenGCPTokenReq: false,
		},
		{
			name:               "almost expire token, no recent fetch",
			tokenExpire:        time.Now().Add(-time.Minute),
			wantGenGCPTokenReq: true,
		},
		{
			name:               "almost expire token, has recent fetch",
			tokenExpire:        time.Now().Add(-time.Minute),
			lastFetch:          time.Now(),
			wantGenGCPTokenReq: true,
		},
		{
			name:               "expired token",
			tokenExpire:        time.Now().Add(-time.Hour),
			wantGenGCPTokenReq: true,
		},
		{
			name:               "expired token, has recent fetch",
			tokenExpire:        time.Now().Add(-time.Hour),
			lastFetch:          time.Now(),
			wantGenGCPTokenReq: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			iam.reset()
			s.gcpAccessToken = &accessToken{
				token:  cachedToken,
				expire: tc.tokenExpire,
			}
			s.gcpAccessLastRequestStarted = tc.lastFetch

			resp, err := srv.Client().Do(r)
			if err != nil {
				t.Fatalf("Do Request failed: %v", err)
			}

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d wants %d", resp.StatusCode, http.StatusOK)
			}

			if iam.hasRequest != tc.wantGenGCPTokenReq {
				t.Errorf("wantGenGCPTokenReq = %v", iam.hasRequest)
			}

			wantToken := cachedToken
			if tc.wantGenGCPTokenReq {
				wantToken = iam.token
			}

			if s.gcpAccessToken.token != wantToken {
				t.Errorf("cached token = %s, want %s", s.gcpAccessToken.token, wantToken)
			}
		})
	}
}

func TestProxyFetchSecret(t *testing.T) {
	s, _, _, _, _, _ := setup(t, &Options{FhirIssuer: issuerURL, Audience: issuerURL, AllowedPathPrefix: []string{"/"}, FhirIssuerClientSecret: "issuer", UseSecretManager: true}, disableCache)

	want := "secret_for_issuer"
	got := s.opts.FhirIssuerClientSecret
	if got != want {
		t.Errorf("opts.FhirIssuerClientSecret = %s, wants %s", got, want)
	}
}

func TestProxyClientCredentials(t *testing.T) {
	claims := simpleClaims("")

	tests := []struct {
		name   string
		opts   *Options
		header map[string]string
	}{
		{
			name: "not require client credentials",
			opts: &Options{FhirIssuer: issuerURL, Audience: issuerURL, AllowedPathPrefix: []string{"/"}},
		},
		{
			name: "require client credentials",
			opts: &Options{FhirIssuer: issuerURL, Audience: issuerURL, ClientsOfProxy: map[string]string{"id": "secret"}, AllowedPathPrefix: []string{"/"}},
			header: map[string]string{
				"X-Client-ID":     "id",
				"X-Client-Secret": "secret",
			},
		},
		{
			name: "require client credentials",
			opts: &Options{FhirIssuer: issuerURL, Audience: issuerURL, ClientsOfProxy: map[string]string{"id": "1"}, AllowedPathPrefix: []string{"/"}, UseSecretManager: true},
			header: map[string]string{
				"X-Client-ID":     "id",
				"X-Client-Secret": "secret_for_1",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, srv, fake, _, oidc, _ := setup(t, tc.opts, disableCache)

			tok, err := oidc.Sign(nil, claims)
			if err != nil {
				t.Fatalf("oidc.Sign() failed: %v", err)
			}

			r, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
			if err != nil {
				t.Fatalf("NewRequest() failed: %v", err)
			}
			for h, v := range tc.header {
				r.Header.Set(h, v)
			}
			r.Header.Set("Connection", "close")
			r.Header.Set("Authorization", "bearer "+tok)
			r.Host = "example.com"

			r.Close = true

			fake.reset(t)
			fake.respContent = "ok-body"
			fake.respStatus = http.StatusOK

			resp, err := srv.Client().Do(r)
			if err != nil {
				t.Fatalf("Do Request failed: %v", err)
			}

			if fake.req == nil {
				t.Errorf("request should reach backend")
			}

			if resp.StatusCode != http.StatusOK {
				t.Errorf("status = %d wants %d", resp.StatusCode, http.StatusOK)
			}
		})
	}
}

func TestProxyClientCredentials_Error(t *testing.T) {
	tests := []struct {
		name   string
		opts   *Options
		header map[string]string
	}{
		{
			name: "missing client id",
			opts: &Options{FhirIssuer: issuerURL, Audience: issuerURL, ClientsOfProxy: map[string]string{"id": "secret"}, AllowedPathPrefix: []string{"/"}},
			header: map[string]string{
				"X-Client-Secret": "secret",
			},
		},
		{
			name: "missing client secret",
			opts: &Options{FhirIssuer: issuerURL, Audience: issuerURL, ClientsOfProxy: map[string]string{"id": "secret"}, AllowedPathPrefix: []string{"/"}},
			header: map[string]string{
				"X-Client-ID": "id",
			},
		},
		{
			name: "unknown client id",
			opts: &Options{FhirIssuer: issuerURL, Audience: issuerURL, ClientsOfProxy: map[string]string{"id": "secret"}, AllowedPathPrefix: []string{"/"}},
			header: map[string]string{
				"X-Client-ID":     "unknown",
				"X-Client-Secret": "secret",
			},
		},
		{
			name: "invalid client secret",
			opts: &Options{FhirIssuer: issuerURL, Audience: issuerURL, ClientsOfProxy: map[string]string{"id": "secret"}, AllowedPathPrefix: []string{"/"}},
			header: map[string]string{
				"X-Client-ID":     "id",
				"X-Client-Secret": "invalid",
			},
		},
		{
			name: "invalid client secret use secret manager",
			opts: &Options{FhirIssuer: issuerURL, Audience: issuerURL, ClientsOfProxy: map[string]string{"id": "1"}, AllowedPathPrefix: []string{"/"}, UseSecretManager: true},
			header: map[string]string{
				"X-Client-ID":     "id",
				"X-Client-Secret": "invalid",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, srv, fake, _, oidc, _ := setup(t, tc.opts, disableCache)

			claims := simpleClaims("")

			tok, err := oidc.Sign(nil, claims)
			if err != nil {
				t.Fatalf("oidc.Sign() failed: %v", err)
			}

			r, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
			if err != nil {
				t.Fatalf("NewRequest() failed: %v", err)
			}
			for h, v := range tc.header {
				r.Header.Set(h, v)
			}
			r.Header.Set("Connection", "close")
			r.Header.Set("Authorization", "bearer "+tok)
			r.Host = "example.com"

			r.Close = true

			fake.reset(t)
			fake.respContent = "ok-body"
			fake.respStatus = http.StatusOK

			resp, err := srv.Client().Do(r)
			if err != nil {
				t.Fatalf("Do Request failed: %v", err)
			}

			if fake.req != nil {
				t.Errorf("request should not reach backend")
			}

			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d wants %d", resp.StatusCode, http.StatusUnauthorized)
			}
		})
	}
}

func TestRequestHeaderFilter(t *testing.T) {
	_, srv, fake, _, oidc, _ := setup(t, &Options{FhirIssuer: issuerURL, Audience: issuerURL, AllowedPathPrefix: []string{"/"}}, disableCache)

	claims := simpleClaims("")

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	wantHeaders := http.Header{
		"Authorization":     []string{"Bearer this-is-a-token"},
		"Accept-Encoding":   []string{"v"},
		"User-Agent":        []string{"v"},
		"If-Modified-Since": []string{"v"},
		"If-None-Match":     []string{"v"},
		"If-Match":          []string{"v"},
		"If-None-Exist":     []string{"v"},
		"Prefer":            []string{"v"},
		"Accept":            []string{"v"},
		"Content-Type":      []string{"v"},
		// GCLB header
		"Via":                    []string{"v"},
		"X-Forwarded-For":        []string{"http://example.com"},
		"X-Forwarded-Proto":      []string{"http"},
		"X-Cloud-Trace-Context":  []string{"v"},
		"X-Http-Method-Override": []string{"v"},
	}

	r, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest() failed: %v", err)
	}
	r.Header = wantHeaders.Clone()
	r.Header.Set("Invalid", "0")
	r.Header.Set("Authorization", "bearer "+tok)
	r.Close = true

	fake.reset(t)
	fake.respContent = "ok-body"
	fake.respStatus = http.StatusOK

	_, err = srv.Client().Do(r)
	if err != nil {
		t.Fatalf("Do Request failed: %v", err)
	}

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url.Parse(%q) failed: %v", srv.URL, err)
	}

	host, _, _ := net.SplitHostPort(u.Host)

	// Smart on FHIR header
	wantHeaders.Set("X-Forwarded-For", "http://example.com, "+host)
	wantHeaders.Set("X-Forwarded-Host", u.Host)
	wantHeaders.Set(fhirSubjectHeader, "sub")
	wantHeaders.Set(fhirIssuerHeader, "https://issuer.example.com")
	wantHeaders.Set(fhirPatientHeader, "user-1")
	wantHeaders.Set(fhirTokenIDHeader, "token-id")
	wantHeaders.Set(authScopeHeader, "openid offline patient/*.read")

	if d := cmp.Diff(wantHeaders, fake.req.Header); len(d) > 0 {
		t.Errorf("Request header to backend (-want, +got): %s", d)
	}
}

func TestResponseHeaderFilter(t *testing.T) {
	_, srv, fake, _, oidc, _ := setup(t, &Options{FhirIssuer: issuerURL, Audience: issuerURL, AllowedPathPrefix: []string{"/"}}, disableCache)

	claims := simpleClaims("")

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	r, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest() failed: %v", err)
	}
	r.Header.Set("Connection", "close")
	r.Header.Set("Authorization", "bearer "+tok)

	r.Close = true

	fake.reset(t)
	fake.respContent = "ok-body"
	fake.respStatus = http.StatusOK
	fake.respHeader = http.Header{
		"ETag":          []string{"0", "1"},
		"Last-Modified": []string{"2"},
		"Content-Type":  []string{"3"},
		"Date":          []string{"4"},
		"Location":      []string{"5"},
		"Invalid":       []string{"6"},
	}

	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatalf("Do Request failed: %v", err)
	}

	wantHeader := http.Header{
		"Etag":           []string{"0", "1"},
		"Last-Modified":  []string{"2"},
		"Content-Type":   []string{"3"},
		"Date":           []string{"4"},
		"Location":       []string{"5"},
		"Content-Length": []string{"7"},
	}

	if d := cmp.Diff(wantHeader, resp.Header); len(d) > 0 {
		t.Errorf("resp header (-want, +got): %s", d)
	}
}

func TestOpaqueTokenWithUserinfo_NoCache(t *testing.T) {
	_, srv, fake, _, _, _ := setup(t, &Options{FhirIssuer: issuerURL, Audience: issuerURL, AllowedPathPrefix: []string{"/"}, UseUserinfoToVerifyAccessToken: true}, disableCache)

	tok := "opaque:undergrad_candice"
	r, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest() failed: %v", err)
	}
	r.Header.Set("Connection", "close")
	r.Header.Set("Authorization", "bearer "+tok)

	r.Close = true

	fake.reset(t)
	fake.respContent = "ok-body"
	fake.respStatus = http.StatusOK

	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatalf("Do Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, wants %d", resp.StatusCode, http.StatusOK)
	}

	wantReq := regexp.MustCompile(`(?s)X-Authorization-Patient: candice.*X-Authorization-Scope: openid profile identities ga4gh_passport_v1 email patient/\*\.read patient/\*\.write.*X-Authorization-Subject: undergrad_candice`)
	if !wantReq.MatchString(fake.reqStr) {
		t.Errorf("req = %q wants %q", fake.reqStr, wantReq.String())
	}
}

func TestOpaqueTokenWithUserinfo_NoCache_Error(t *testing.T) {
	_, srv, fake, _, _, _ := setup(t, &Options{FhirIssuer: issuerURL, Audience: issuerURL, AllowedPathPrefix: []string{"/"}, UseUserinfoToVerifyAccessToken: true}, disableCache)

	tok := "opaque:invalid"
	r, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest() failed: %v", err)
	}
	r.Header.Set("Connection", "close")
	r.Header.Set("Authorization", "bearer "+tok)

	r.Close = true

	fake.reset(t)
	fake.respContent = "ok-body"
	fake.respStatus = http.StatusOK

	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatalf("Do Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, wants %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestOpaqueTokenWithUserinfo_WithCache(t *testing.T) {
	_, srv, fake, _, _, redis := setup(t, &Options{FhirIssuer: issuerURL, Audience: issuerURL, AllowedPathPrefix: []string{"/"}, UseUserinfoToVerifyAccessToken: true}, enableCache)

	tok := "opaque:undergrad_candice"
	r, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest() failed: %v", err)
	}
	r.Header.Set("Connection", "close")
	r.Header.Set("Authorization", "bearer "+tok)

	r.Close = true

	fake.reset(t)
	fake.respContent = "ok-body"
	fake.respStatus = http.StatusOK

	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatalf("Do Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, wants %d", resp.StatusCode, http.StatusOK)
	}

	wantReq := regexp.MustCompile(`(?s)X-Authorization-Patient: candice.*X-Authorization-Scope: openid profile identities ga4gh_passport_v1 email patient/\*\.read patient/\*\.write.*X-Authorization-Subject: undergrad_candice`)
	if !wantReq.MatchString(fake.reqStr) {
		t.Errorf("req = %q wants %q", fake.reqStr, wantReq.String())
	}

	key := auth.AccessTokenCacheKey(issuerURL, tok)
	// not found will also return err
	value, err := redis.Get(key)
	if err != nil {
		t.Errorf("cache.Get() failed: %v", err)
	}

	ttl := int64(redis.TTL(key).Seconds())
	if ttl > int64(cacheMaxExpiry.Seconds()) {
		t.Errorf("ttl = %d, wants %d", ttl, cacheMaxExpiry)
	}

	// verify the token with cache
	resp, err = srv.Client().Do(r)
	if err != nil {
		t.Fatalf("Do Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, wants %d", resp.StatusCode, http.StatusOK)
	}

	// save the value to another key, the token can not be verify in oidc server.
	tok = "opaque:key"
	key = auth.AccessTokenCacheKey(issuerURL, tok)
	redis.Set(key, value)
	redis.SetTTL(key, cacheMaxExpiry)

	r2, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	if err != nil {
		t.Fatalf("NewRequest() failed: %v", err)
	}
	r2.Header.Set("Connection", "close")
	r2.Header.Set("Authorization", "bearer "+tok)

	r2.Close = true

	resp, err = srv.Client().Do(r2)
	if err != nil {
		t.Fatalf("Do Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, wants %d", resp.StatusCode, http.StatusOK)
	}

	// verify the token expiried in cache
	redis.FastForward(2 * cacheMaxExpiry)

	// valid token and expired cache
	resp, err = srv.Client().Do(r)
	if err != nil {
		t.Fatalf("Do Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, wants %d", resp.StatusCode, http.StatusOK)
	}

	// invalid token and expired cache
	resp, err = srv.Client().Do(r2)
	if err != nil {
		t.Fatalf("Do Request failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, wants %d", resp.StatusCode, http.StatusUnauthorized)
	}

}

func TestScopeParse(t *testing.T) {
	tests := []struct {
		name      string
		scope     string
		wantScope string
	}{
		{
			name:      "escaped line breaker as a item of scope",
			scope:     "\\n aaa",
			wantScope: "\\n aaa",
		},
		{
			name:      "escaped line breaker in a item of scope",
			scope:     "aa\\na aaa",
			wantScope: "aa\\na aaa",
		},
		{
			name:      "* as a item of scope",
			scope:     "* aaa",
			wantScope: "* aaa",
		},
		{
			name:      "* in a item of scope",
			scope:     "aa*a aaa",
			wantScope: "aa*a aaa",
		},
		{
			name:      ". as a item of scope",
			scope:     ". aaa",
			wantScope: ". aaa",
		},
		{
			name:      ". in a item of scope",
			scope:     "aa.a aaa",
			wantScope: "aa.a aaa",
		},
		{
			name:      "unicode as a item of scope",
			scope:     "😊 aaa",
			wantScope: "😊 aaa",
		},
		{
			name:      "unicode in a item of scope",
			scope:     "aa😊a aaa",
			wantScope: "aa😊a aaa",
		},
	}

	_, srv, fake, _, oidc, _ := setup(t, &Options{FhirIssuer: issuerURL, Audience: issuerURL, AllowedPathPrefix: []string{"/"}}, disableCache)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := simpleClaims(tc.scope)

			tok, err := oidc.Sign(nil, claims)
			if err != nil {
				t.Fatalf("oidc.Sign() failed: %v", err)
			}

			r, err := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
			if err != nil {
				t.Fatalf("NewRequest() failed: %v", err)
			}
			r.Header.Set("Connection", "close")
			r.Header.Set("Authorization", "bearer "+tok)

			r.Close = true

			fake.reset(t)
			fake.respContent = "ok-body"
			fake.respStatus = http.StatusOK

			_, err = srv.Client().Do(r)
			if err != nil {
				t.Fatalf("Do Request failed: %v", err)
			}

			got := fake.req.Header.Get(authScopeHeader)
			if d := cmp.Diff(tc.wantScope, got); len(d) > 0 {
				t.Errorf("scope in header (-want, +got): %s", d)
			}
		})
	}
}

var (
	issuerURL = "https://issuer.example.com"
)

func setup(t *testing.T, opts *Options, useCache bool) (*Service, *httptest.Server, *fakeBackendService, *fakeIAM, *fakeoidcissuer.Server, *miniredis.Miniredis) {
	t.Helper()

	oidc, err := fakeoidcissuer.New(issuerURL, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _, _, _) failed: %v", issuerURL, err)
	}

	auth.HTTPClient = oidc.Client()

	f := &fakeBackendService{}
	backendRouter := mux.NewRouter()
	backendRouter.PathPrefix("/").HandlerFunc(f.handler)
	backend := httptest.NewServer(backendRouter)

	opts.ProxyTo = backend.URL
	frontendRouter := mux.NewRouter()
	// Add a path not for proxy.
	frontendRouter.HandleFunc("/liveness", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("liveness body"))
	})
	fakeIAM := &fakeIAM{}
	fakeIAM.reset()

	fakeSecret := &fakeSecretClient{}

	var cacheClient func() cache.Client
	var redis *miniredis.Miniredis
	if useCache {
		redis, err = miniredis.Run()
		if err != nil {
			t.Fatalf("miniredis.Run() failed: %v", err)
		}
		pool := rediz.NewPool(redis.Addr())

		cacheClient = func() cache.Client {
			return pool.Client()
		}

		t.Cleanup(func() {
			pool.Close()
			redis.Close()
		})
	}

	s, err := New(context.Background(), frontendRouter, opts, nil, fakeIAM, fakeSecret, cacheClient)
	if err != nil {
		t.Fatalf("New proxy failed: %v", err)
	}
	frontend := httptest.NewServer(frontendRouter)

	t.Cleanup(func() {
		frontend.Close()
		backend.Close()
		auth.HTTPClient = nil
	})

	return s, frontend, f, fakeIAM, oidc, redis
}

type fakeBackendService struct {
	t           *testing.T
	req         *http.Request
	reqStr      string
	respContent string
	respStatus  int
	respHeader  http.Header
}

func (s *fakeBackendService) reset(t *testing.T) {
	s.t = t
	s.req = nil
	s.reqStr = ""
}

func (s *fakeBackendService) handler(w http.ResponseWriter, r *http.Request) {
	s.req = r.Clone(r.Context())
	s.reqStr = requestToString(s.t, r)
	for k, v := range s.respHeader {
		for _, val := range v {
			w.Header().Add(k, val)
		}
	}
	w.WriteHeader(s.respStatus)
	w.Write([]byte(s.respContent))
}

type fakeIAM struct {
	token      string
	respErr    bool
	hasRequest bool
}

func (s *fakeIAM) GenerateAccessToken(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error) {
	s.hasRequest = true
	if s.respErr {
		return nil, status.Errorf(codes.InvalidArgument, "example-error")
	}
	return &credentialspb.GenerateAccessTokenResponse{AccessToken: s.token, ExpireTime: timeutil.TimestampProto(time.Now().Add(req.Lifetime.AsDuration()))}, nil
}

func (s *fakeIAM) reset() {
	s.token = "this-is-a-token"
	s.hasRequest = false
	s.respErr = false
}

func requestToString(t *testing.T, req *http.Request) string {
	b, err := httputil.DumpRequest(req, true)
	if err != nil {
		t.Fatalf("DumpRequest failed: %v", err)
	}
	return string(b)
}

func responseToString(t *testing.T, resp *http.Response) string {
	b, err := httputil.DumpResponse(resp, true)
	if err != nil {
		t.Fatalf("DumpResponse failed: %v", err)
	}
	return string(b)
}

func simpleClaims(scope string) *ga4gh.Identity {
	if len(scope) == 0 {
		scope = "openid offline patient/*.read"
	}
	now := time.Now().Unix()
	return &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "sub",
		Scope:     scope,
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: []string{issuerURL},
		Patient:   "user-1",
		ID:        "token-id",
	}
}

type fakeSecretClient struct {
}

func (s *fakeSecretClient) GetSecret(ctx context.Context, key string) (string, error) {
	return "secret_for_" + key, nil
}
