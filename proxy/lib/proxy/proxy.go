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

// Package proxy includes a smart on fhir reverse proxy.
package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/logging" /* copybara-comment */
	"github.com/googleapis/gax-go/v2" /* copybara-comment */
	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"bitbucket.org/creachadair/stringset" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auth" /* copybara-comment: auth */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/cache" /* copybara-comment: cache */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	glog "github.com/golang/glog" /* copybara-comment */
	credentialspb "google.golang.org/genproto/googleapis/iam/credentials/v1" /* copybara-comment: common_go_proto */
)

const (
	clientIDHeader     = "X-Client-ID"
	clientSecretHeader = "X-Client-Secret"
	fhirSubjectHeader  = "X-Authorization-Subject"
	fhirIssuerHeader   = "X-Authorization-Issuer"
	fhirPatientHeader  = "X-Authorization-Patient"
	fhirTokenIDHeader  = "X-Authorization-Token-Id"
	authScopeHeader    = "X-Authorization-Scope"
	consentScopeHeader = "X-Consent-Scope"

	// gcpAccessTokenLifeTime is the life time used to request new token.
	gcpAccessTokenLifeTime = 15 * time.Minute

	// gcpAccessTokenFetchAhead is the time to request new token before the token expired.
	gcpAccessTokenFetchAhead = 2 * time.Minute

	// gcpAccessTokenFetchInterval is the interval we use to pre fetch the token.
	gcpAccessTokenFetchInterval = 10 * time.Second
)

var (
	allowedRequestHeader = stringset.New(
		http.CanonicalHeaderKey("Authorization"),
		http.CanonicalHeaderKey("Accept-Encoding"),
		http.CanonicalHeaderKey("User-Agent"),
		http.CanonicalHeaderKey("If-Modified-Since"),
		http.CanonicalHeaderKey("If-None-Match"),
		http.CanonicalHeaderKey("If-Match"),
		http.CanonicalHeaderKey("If-None-Exist"),
		http.CanonicalHeaderKey("Prefer"),
		http.CanonicalHeaderKey("Accept"),
		http.CanonicalHeaderKey("Content-Type"),
		http.CanonicalHeaderKey("Content-Length"),
		http.CanonicalHeaderKey("Connection"),
		// GCLB header
		http.CanonicalHeaderKey("Via"),
		http.CanonicalHeaderKey("X-Forwarded-For"),
		http.CanonicalHeaderKey("X-Forwarded-Proto"),
		http.CanonicalHeaderKey("X-Cloud-Trace-Context"),
		http.CanonicalHeaderKey("X-HTTP-Method-Override"),
		// Smart on FHIR header
		http.CanonicalHeaderKey("X-Forwarded-Host"),
		http.CanonicalHeaderKey(clientIDHeader),
		http.CanonicalHeaderKey(clientSecretHeader),
		http.CanonicalHeaderKey(fhirSubjectHeader),
		http.CanonicalHeaderKey(fhirIssuerHeader),
		http.CanonicalHeaderKey(fhirPatientHeader),
		http.CanonicalHeaderKey(fhirTokenIDHeader),
		http.CanonicalHeaderKey(authScopeHeader),
		http.CanonicalHeaderKey(consentScopeHeader),
	)
	allowedResponseHeader = stringset.New(
		http.CanonicalHeaderKey("ETag"),
		http.CanonicalHeaderKey("Last-Modified"),
		http.CanonicalHeaderKey("Content-Type"),
		http.CanonicalHeaderKey("Content-Length"),
		http.CanonicalHeaderKey("Date"),
		http.CanonicalHeaderKey("Location"),
		http.CanonicalHeaderKey("Content-Encoding"),
	)

	// Transport used in proxy
	Transport = http.DefaultTransport

	// Consent scopes pattern
	consentScopePattern = regexp.MustCompile(`^(btg|bypass|(actor|purp|env)/.+)$`)
)

// New adds the proxy to server router.
func New(ctx context.Context, r *mux.Router, opts *Options, logger *logging.Client, iamClient IAMClient, secretManagerClient SecretManagerClient, cacheClient func() cache.Client) (*Service, error) {
	u, err := url.Parse(opts.ProxyTo)
	if err != nil {
		return nil, fmt.Errorf("url.Parse(%s): %v", opts.ProxyTo, err)
	}

	s := &Service{
		opts:                        opts,
		fhirProxy:                   httputil.NewSingleHostReverseProxy(u),
		iamClient:                   iamClient,
		secretManagerClient:         secretManagerClient,
		gcpAccessLastRequestStarted: time.Now(),
	}

	issSec, err := s.fetchFhirIssuerClientSecret(ctx)
	if err != nil {
		return nil, err
	}
	if len(issSec) > 0 {
		s.opts.FhirIssuerClientSecret = issSec
	}

	clients, err := s.fetchClientsOfProxySecret(ctx)
	if err != nil {
		return nil, err
	}
	if len(clients) > 0 {
		s.opts.ClientsOfProxy = clients
	}

	tok, expire, err := s.fetchAccessTokenForSA(ctx)
	if err != nil {
		return nil, fmt.Errorf("request access token for service account failed: %v", err)
	}
	// Lock is not needed at service bootstrap.
	s.lockedUpdateToken(tok, expire)

	proxyDirector(s.fhirProxy)
	responseHeaderFilter(s.fhirProxy)
	s.fhirProxy.Transport = Transport

	checker := auth.NewChecker(logger, opts.FhirIssuer, nil, nil, nil, opts.UseUserinfoToVerifyAccessToken, cacheClient)
	r.PathPrefix("/.well-known/smart-configuration").HandlerFunc(auth.MustWithAuth(s.wellKnownSmartConfigure, checker, auth.RequireNone))
	r.PathPrefix("/").HandlerFunc(auth.MustWithAuth(s.proxy, checker, auth.Require{Role: auth.User, SelfClientID: opts.Audience}))

	return s, nil
}

type accessToken struct {
	token  string
	expire time.Time
}

// Service of the smart on fhir proxy.
type Service struct {
	opts                        *Options
	fhirProxy                   *httputil.ReverseProxy
	iamClient                   IAMClient
	gcpAccessToken              *accessToken
	gcpAccessLastRequestStarted time.Time
	gcpAccessTokenFetchLock     sync.Mutex
	secretManagerClient         SecretManagerClient
	cache                       cache.Client
}

// WellKnownSmartConfigureResponse response of /.well-known/smart-configuration
type WellKnownSmartConfigureResponse struct {
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	Capabilities          []string `json:"capabilities"`
}

func (s *Service) wellKnownSmartConfigure(w http.ResponseWriter, r *http.Request) {
	res := &WellKnownSmartConfigureResponse{
		AuthorizationEndpoint: s.opts.WellKnownAuthorizationEndpoint,
		TokenEndpoint:         s.opts.WellKnownTokenEndpoint,
		Capabilities:          s.opts.WellKnownCapabilities,
	}
	w.Header().Set("Content-Type", "application/json")
	httputils.WriteCorsHeaders(w)
	httputils.EncodeJSON(w, res)
}

func (s *Service) proxy(w http.ResponseWriter, r *http.Request) {
	cloned := r.Clone(r.Context())

	if err := s.verifyClientCredentials(r); err != nil {
		httputils.WriteError(w, err)
		return
	}

	if err := s.verifyRequestPath(r); err != nil {
		httputils.WriteError(w, err)
		return
	}

	a, err := auth.FromContext(r.Context())
	if err != nil {
		httputils.WriteError(w, status.Errorf(status.Code(err), "read identity failed: %v", err))
		return
	}

	tok, err := s.getAccessTokenForSA(r.Context())
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.Unavailable, "getAccessTokenForSA() failed: %v", err))
		return
	}

	cloned.Header.Set("Authorization", "Bearer "+tok)

	idToFhirHeader(a.ID, s.opts.RemoveScopes, cloned)

	s.fhirProxy.ServeHTTP(w, cloned)
}

// IAMClient used to request AccessToken on GCP for ServiceAccount.
type IAMClient interface {
	GenerateAccessToken(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error)
}

// SecretManagerClient used to fetch secret from GCP SecretManager.
type SecretManagerClient interface {
	GetSecret(ctx context.Context, key string) (string, error)
}

func (s *Service) fetchFhirIssuerClientSecret(ctx context.Context) (string, error) {
	if !s.opts.UseSecretManager {
		return "", nil
	}

	if s.secretManagerClient == nil {
		return "", fmt.Errorf("need to fetch secret but no SecretManagerClient pass in")
	}

	if len(s.opts.FhirIssuerClientSecret) == 0 {
		return "", nil
	}

	return s.secretManagerClient.GetSecret(ctx, s.opts.FhirIssuerClientSecret)
}

func (s *Service) fetchClientsOfProxySecret(ctx context.Context) (map[string]string, error) {
	if !s.opts.UseSecretManager {
		return nil, nil
	}

	if s.secretManagerClient == nil {
		return nil, fmt.Errorf("need to fetch secret but no SecretManagerClient pass in")
	}

	clients := map[string]string{}
	for id, key := range s.opts.ClientsOfProxy {
		sec, err := s.secretManagerClient.GetSecret(ctx, key)
		if err != nil {
			return nil, err
		}

		clients[id] = sec
	}

	return clients, nil
}

func (s *Service) getAccessTokenForSA(ctx context.Context) (string, error) {
	s.gcpAccessTokenFetchLock.Lock()
	defer s.gcpAccessTokenFetchLock.Unlock()

	now := time.Now()
	if now.Before(s.gcpAccessToken.expire) {
		// token still valid, check if we need to pre fetch before expired.
		s.lockedMaybePrefetchNextToken(ctx, now)
	} else {
		tok, expire, err := s.fetchAccessTokenForSA(ctx)
		if err != nil {
			return "", err
		}
		s.lockedUpdateToken(tok, expire)
	}

	return s.gcpAccessToken.token, nil
}

func (s *Service) lockedMaybePrefetchNextToken(ctx context.Context, now time.Time) {
	// check if we don't need to fetch because the token doesn't expire for a while
	if now.Add(gcpAccessTokenFetchAhead).Before(s.gcpAccessToken.expire) {
		return
	}

	// prefetch a new token on a new go routine that will not have the lock.
	go s.unlockFetchAccessTokenForSA(ctx)
}

func (s *Service) unlockFetchAccessTokenForSA(ctx context.Context) {
	// call this only if you do not already hold the fetch lock.
	s.gcpAccessTokenFetchLock.Lock()
	defer s.gcpAccessTokenFetchLock.Unlock()

	now := time.Now()

	// don't prefetch if there is a recent token refresh in flight.
	if now.Before(s.gcpAccessLastRequestStarted.Add(gcpAccessTokenFetchInterval)) {
		return
	}
	s.gcpAccessLastRequestStarted = now

	tok, expire, err := s.fetchAccessTokenForSA(ctx)
	if err != nil {
		glog.Errorf("unable to fetch access token for SA, maybe iam/credentials experincing issue: %v", err)
		return
	}
	s.lockedUpdateToken(tok, expire)
}

func (s *Service) fetchAccessTokenForSA(ctx context.Context) (string, time.Time, error) {
	resp, err := s.iamClient.GenerateAccessToken(ctx, &credentialspb.GenerateAccessTokenRequest{
		Name:     resourceName0fSA(s.opts.ServiceAccountName),
		Scope:    []string{"https://www.googleapis.com/auth/cloud-platform"},
		Lifetime: timeutil.DurationProto(gcpAccessTokenLifeTime),
	})

	if err != nil {
		return "", time.Time{}, err
	}

	// expires the token 10 seconds ahead as request may take some time to process and transfer to fhir backend.
	return resp.AccessToken, resp.ExpireTime.AsTime().Add(-gcpAccessTokenFetchInterval), nil
}

func (s *Service) lockedUpdateToken(token string, expire time.Time) {
	s.gcpAccessToken = &accessToken{
		token:  token,
		expire: expire,
	}
}

func resourceName0fSA(sa string) string {
	return fmt.Sprintf("projects/-/serviceAccounts/%s", sa)
}

func idToFhirHeader(id *ga4gh.Identity, removeScopes stringset.Set, r *http.Request) {
	r.Header.Del(clientSecretHeader)
	r.Header.Set(fhirTokenIDHeader, id.ID)

	var authScope, consentScope []string
	for _, scope := range strings.Split(id.Scope, " ") {
		if len(scope) == 0 {
			continue
		}
		if removeScopes.Contains(scope) {
			continue
		}
		if consentScopePattern.MatchString(scope) {
			consentScope = append(consentScope, scope)
		} else {
			authScope = append(authScope, scope)
		}
	}
	if len(authScope) > 0 {
		r.Header.Set(authScopeHeader, strings.Join(authScope, " "))
		// TODO: consider always populating these headers.
		r.Header.Set(fhirSubjectHeader, id.Subject)
		r.Header.Set(fhirIssuerHeader, id.Issuer)
		r.Header.Set(fhirPatientHeader, id.Patient)
	}
	if len(consentScope) > 0 {
		r.Header.Set(consentScopeHeader, strings.Join(consentScope, " "))
	}
}

func (s *Service) verifyClientCredentials(r *http.Request) error {
	// Check if client credentials are not required
	if len(s.opts.ClientsOfProxy) == 0 {
		return nil
	}

	clientID := r.Header.Get(clientIDHeader)
	clientSecret := r.Header.Get(clientSecretHeader)

	if len(clientID) == 0 {
		return status.Errorf(codes.Unauthenticated, "missing header: %q", clientIDHeader)
	}

	if len(clientSecret) == 0 {
		return status.Errorf(codes.Unauthenticated, "missing header: %q", clientSecretHeader)
	}

	secret, ok := s.opts.ClientsOfProxy[clientID]
	if !ok {
		return status.Errorf(codes.Unauthenticated, "unknown client id %q in header", clientID)
	}

	if secret != clientSecret {
		return status.Errorf(codes.Unauthenticated, "invalid client secret for client %q in header", clientID)
	}

	return nil
}

func (s *Service) verifyRequestPath(r *http.Request) error {
	// TODO: consider use trie to improve the performance.
	for _, prefix := range s.opts.AllowedPathPrefix {
		if strings.HasPrefix(r.URL.Path, prefix) {
			return nil
		}
	}
	return status.Errorf(codes.NotFound, "path %q not found", r.URL.Path)
}

func proxyDirector(proxy *httputil.ReverseProxy) {
	defaultDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		host := r.Host
		if defaultDirector != nil {
			defaultDirector(r)
		}
		fixHostInProxyDirector(r, host)
		requestHeaderFilter(r)
	}
}

// requestHeaderFilter only allowed header show added to the request.
func requestHeaderFilter(r *http.Request) {
	for key := range r.Header.Clone() {
		if !allowedRequestHeader.Contains(key) {
			r.Header.Del(key)
		}
	}
}

func fixHostInProxyDirector(r *http.Request, host string) {
	// Workaround for golang issue https://github.com/golang/go/issues/28168.
	// Because golang ReverseProxy is using req.Host if it is not empty to make
	// the request to backend. But setting req.Host may also overwrite the Host
	// in the header, depends on http/1 or http/2. https://golang.org/pkg/net/http/#Request
	// In this func, we copy the host to header Host and X-Forwarded-Host for more
	// footprint and we set the X-Forwarded-Proto header if not set, then overwrite
	// the req.Host with req.URL.Host because req.URL.Host has set by defaultDirector.
	// This workaround will not break even golang ReverseProxy fix this issue.
	// In Go 1.20, the X-Forwarded-Host and X-Forwarded-Proto headers are set by
	// default (see https://github.com/golang/go/issues/50465)
	if len(r.Header.Get("X-Forwarded-Host")) == 0 {
		r.Header.Set("X-Forwarded-Host", host)
	}
	if len(r.Header.Get("X-Forwarded-Proto")) == 0 {
		if r.TLS == nil {
			r.Header.Set("X-Forwarded-Proto", "http")
		} else {
			r.Header.Set("X-Forwarded-Proto", "https")
		}
	}
	r.Header.Set("Host", host)
	r.Host = r.URL.Host
}

// responseHeaderFilter only allowed header show added to the response.
func responseHeaderFilter(proxy *httputil.ReverseProxy) {
	modifier := proxy.ModifyResponse
	proxy.ModifyResponse = func(resp *http.Response) error {
		if modifier != nil {
			if err := modifier(resp); err != nil {
				return err
			}
		}
		for key := range resp.Header.Clone() {
			if !allowedResponseHeader.Contains(key) {
				resp.Header.Del(key)
			}
		}
		return nil
	}
}
