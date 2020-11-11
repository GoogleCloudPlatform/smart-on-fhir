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

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/cenkalti/backoff" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/localsign" /* copybara-comment: localsign */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */

	glog "github.com/golang/glog" /* copybara-comment */
)

var (
	enabled     = flag.Bool("e2etest", false, "enable e2e testing, default is false")
	proxyURL    = flag.String("proxy", "", "the url to reach the Smart on FHIR proxy")
	chcEndpoint = flag.String("chc", "https://healthcare.googleapis.com", "the testing GCP healthcare endpoint")
	project     = flag.String("project", "", "the testing GCP project which host the dataset")
	apiVersion  = flag.String("apiVersion", "v1alpha2", "the version of FHIR api")
	location    = flag.String("location", "us-central1", "the location to test")
	issuerURL   = flag.String("iss", "http://persona:8081/oidc", "issuer used to verify the access token")
	aud         = flag.String("aud", "proxy-client-id", "proxy expected audience in token")
)

type resource struct {
	id      string
	resType string
	body    map[string]interface{}
}

var (
	// Patient who will own the main patient compartment.
	rootPatient = &resource{
		id:      "root-id",
		resType: "Patient",
		body: map[string]interface{}{
			"id":           "root-id",
			"resourceType": "Patient",
			"language":     "abc",
		},
	}

	// Patient that will exist but not be in root's compartment. This patient's id
	// is a valid SMART patient context that will not grant access to any members
	// of the root patient's compartment.
	otherPatient = &resource{
		id:      "other-id",
		resType: "Patient",
		body: map[string]interface{}{
			"id":           "other-id",
			"resourceType": "Patient",
			"language":     "abc",
		},
	}

	// Member of root patient compartment.
	account = &resource{
		id:      "account-id",
		resType: "Account",
		body: map[string]interface{}{
			"id":           "account-id",
			"resourceType": "Account",
			"status":       "active",
			"subject": []map[string]string{{
				"reference": fmt.Sprintf("Patient/%s", rootPatient.id),
			}},
		},
	}
)

type config struct {
	version, project, location, dataset, store string
}

func (c config) datasetPrefix() string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/datasets", c.version, c.project, c.location)
}

func (c config) datasetName() string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/datasets/%s", c.version, c.project, c.location, c.dataset)
}

func (c config) storePrefix() string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/datasets/%s/fhirStores", c.version, c.project, c.location, c.dataset)
}

func (c config) storeName() string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/datasets/%s/fhirStores/%s", c.version, c.project, c.location, c.dataset, c.store)
}

func universalClaims(scope, patient string) *ga4gh.Identity {
	now := time.Now().Unix()
	return &ga4gh.Identity{
		Scope:     scope,
		Patient:   patient,
		Issuer:    *issuerURL,
		Subject:   "sub",
		IssuedAt:  now - 1000,
		Expiry:    now + 10000,
		Audiences: []string{*aud},
		ID:        "token-id",
	}
}

// TODO: Explore reusing g/c/h/test libs.
func sendRequest(t *testing.T, method, path string, body interface{}, headers map[string]string, tokenClaims *ga4gh.Identity) *http.Response {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("json.Marshal(%+v) failed: %v", body, err)
		}
		bodyReader = bytes.NewBuffer(b)
	}

	req, err := http.NewRequest(method, *proxyURL+"/"+path, bodyReader)
	if err != nil {
		t.Fatalf("http.NewRequest(%q, %q, body) failed: %v", method, *proxyURL+"/"+path, err)
	}
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	signer := localsign.New(&testkeys.PersonaBrokerKey)
	tok, err := signer.SignJWT(context.Background(), tokenClaims, nil)
	if err != nil {
		t.Fatalf("signer.SignJWT() failed: %v", err)
	}

	req.Header.Add("Authorization", "Bearer "+tok)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http.DefaultClient.Do(req) failed: %v", err)
	}

	return resp
}

func setup(t *testing.T) config {
	// Create a dataset and a store with random IDs.
	c := config{
		version:  *apiVersion,
		project:  *project,
		location: *location,
		dataset:  uuid.New(),
		store:    uuid.New(),
	}

	// Create dataset.
	headers := map[string]string{"Content-Type": "application/json; charset=utf-8"}
	body := map[string]interface{}{}
	resp := sendRequest(t, http.MethodPost, fmt.Sprintf("%s?dataset_id=%s", c.datasetPrefix(), c.dataset), body, headers, universalClaims("user/*.*", ""))
	if resp.StatusCode != http.StatusOK {
		b, _ := ioutil.ReadAll(resp.Body)
		t.Fatalf("failed to create dataset; resp status =%d, wants %d; message=%s", resp.StatusCode, http.StatusOK, string(b))
	}
	// Create store.
	body = map[string]interface{}{
		"enableUpdateCreate": true,
		"version":            "R4",
	}
	opt := backoff.NewExponentialBackOff()
	opt.MaxElapsedTime = 20 * time.Second
	if err := backoff.Retry(func() error {
		resp = sendRequest(t, http.MethodPost, fmt.Sprintf("%s?fhir_store_id=%s", c.storePrefix(), c.store), body, headers, universalClaims("user/*.*", ""))
		if resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("dataset %s is still initializing", c.datasetName())
		}
		if resp.StatusCode != http.StatusOK {
			b, _ := ioutil.ReadAll(resp.Body)
			return backoff.Permanent(fmt.Errorf("resp status =%d, wants %d; message=%s", resp.StatusCode, http.StatusOK, string(b)))
		}
		return nil
	}, opt); err != nil {
		t.Fatalf("failed to create store; %v", err)
	}

	prepopulateStore(t, c.storeName())

	return c
}

func cleanup(t *testing.T, c config) {
	// Delete the dataset, which in turns deletes the store.
	resp := sendRequest(t, http.MethodDelete, c.datasetName(), nil, nil, universalClaims("user/*.*", ""))
	if resp.StatusCode != http.StatusOK {
		b, _ := ioutil.ReadAll(resp.Body)
		t.Errorf("failed to delete dataset; resp status =%d, wants %d; message=%s", resp.StatusCode, http.StatusOK, string(b))
	}
}

func prepopulateStore(t *testing.T, storeName string) {
	t.Helper()

	createOrUpdate(t, storeName, rootPatient)
	createOrUpdate(t, storeName, otherPatient)
	createOrUpdate(t, storeName, account)
}

func createOrUpdate(t *testing.T, storeName string, res *resource) {
	t.Helper()
	headers := map[string]string{"Content-Type": "application/fhir+json;charset=utf-8"}
	path := fmt.Sprintf("%s/fhir/%s/%s", storeName, res.resType, res.id)

	resp := sendRequest(t, http.MethodPut, path, res.body, headers, universalClaims("system/*.*", ""))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := ioutil.ReadAll(resp.Body)
		t.Fatalf("failed to create or update resource; resp status =%d, wants %d; message=%s", resp.StatusCode, http.StatusOK, string(b))
	}
}

func TestCreate(t *testing.T) {
	c := setup(t)
	defer cleanup(t, c)

	tests := []struct {
		name       string
		scopes     string
		patient    string
		body       map[string]interface{}
		wantStatus int
	}{
		{
			name:   "access granted",
			scopes: "user/Patient.*",
			body: map[string]interface{}{
				"resourceType": "Patient",
			},
			wantStatus: http.StatusCreated,
		},
		{
			name:   "access denied",
			scopes: "user/Observation.* user/Patient.read",
			body: map[string]interface{}{
				"resourceType": "Patient",
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:    "compartment restricted access granted to compartment member",
			scopes:  "patient/Account.*",
			patient: rootPatient.id,
			body: map[string]interface{}{
				"resourceType": "Account",
				"status":       "active",
				"subject": []map[string]string{{
					"reference": fmt.Sprintf("Patient/%s", rootPatient.id),
				}},
			},
			wantStatus: http.StatusCreated,
		},
		{
			name:    "compartment restricted access denied to non compartment member",
			scopes:  "patient/Account.*",
			patient: otherPatient.id,
			body: map[string]interface{}{
				"resourceType": "Account",
				"status":       "active",
				"subject": []map[string]string{{
					"reference": fmt.Sprintf("Patient/%s", rootPatient.id),
				}},
			},
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{"Content-Type": "application/fhir+json;charset=utf-8"}
			path := fmt.Sprintf("%s/fhir/%s", c.storeName(), tc.body["resourceType"])

			resp := sendRequest(t, http.MethodPost, path, tc.body, headers, universalClaims(tc.scopes, tc.patient))
			if resp.StatusCode != tc.wantStatus {
				b, _ := ioutil.ReadAll(resp.Body)
				t.Errorf("fhir.create got unexpected resp status=%d, want=%d; message=%s", resp.StatusCode, tc.wantStatus, string(b))
			}
		})
	}
}

func TestUpdate(t *testing.T) {
	c := setup(t)
	defer cleanup(t, c)

	tests := []struct {
		name       string
		scopes     string
		patient    string
		updated    *resource
		wantStatus int
	}{
		{
			name:   "access granted",
			scopes: "user/Patient.*",
			updated: &resource{
				resType: rootPatient.resType,
				id:      rootPatient.id,
				body: map[string]interface{}{
					"id":           rootPatient.id,
					"resourceType": rootPatient.resType,
					"language":     "xyz",
				},
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "access denied",
			scopes: "user/Observation.* user/Patient.read",
			updated: &resource{
				resType: rootPatient.resType,
				id:      rootPatient.id,
				body: map[string]interface{}{
					"id":           rootPatient.id,
					"resourceType": rootPatient.resType,
					"language":     "xyz",
				},
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:    "compartment restricted access granted to compartment member",
			scopes:  "patient/Account.*",
			patient: rootPatient.id,
			updated: &resource{
				resType: account.resType,
				id:      account.id,
				body: map[string]interface{}{
					"id":           account.id,
					"resourceType": "Account",
					"status":       "inactive",
					"subject": []map[string]string{{
						"reference": fmt.Sprintf("Patient/%s", rootPatient.id),
					}},
				},
			},
			wantStatus: http.StatusOK,
		},
		{
			name:    "compartment restricted access denied to non compartment member",
			scopes:  "patient/Account.*",
			patient: otherPatient.id,
			updated: &resource{
				resType: account.resType,
				id:      account.id,
				body: map[string]interface{}{
					"id":           account.id,
					"resourceType": "Account",
					"status":       "inactive",
					"subject": []map[string]string{{
						"reference": fmt.Sprintf("Patient/%s", rootPatient.id),
					}},
				},
			},
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{"Content-Type": "application/fhir+json;charset=utf-8"}
			path := fmt.Sprintf("%s/fhir/%s/%s", c.storeName(), tc.updated.resType, tc.updated.id)

			resp := sendRequest(t, http.MethodPut, path, tc.updated.body, headers, universalClaims(tc.scopes, tc.patient))
			if resp.StatusCode != tc.wantStatus {
				b, _ := ioutil.ReadAll(resp.Body)
				t.Errorf("fhir.update got unexpected resp status=%d, want=%d; message=%s", resp.StatusCode, tc.wantStatus, string(b))
			}
		})
	}
}

func TestPatch(t *testing.T) {
	c := setup(t)
	defer cleanup(t, c)

	tests := []struct {
		name       string
		scopes     string
		patient    string
		patch      []map[string]interface{}
		resource   *resource
		wantStatus int
	}{
		{
			name:   "access granted",
			scopes: "user/Patient.*",
			patch: []map[string]interface{}{{
				"op":    "add",
				"path":  "/language",
				"value": "xyz",
			}},
			resource:   rootPatient,
			wantStatus: http.StatusOK,
		},
		{
			name:   "access denied",
			scopes: "user/Observation.* user/Patient.read",
			patch: []map[string]interface{}{{
				"op":    "add",
				"path":  "/language",
				"value": "xyz",
			}},
			resource:   rootPatient,
			wantStatus: http.StatusForbidden,
		},
		{
			name:    "compartment restricted access granted to compartment member",
			scopes:  "patient/Account.*",
			patient: rootPatient.id,
			patch: []map[string]interface{}{{
				"op":    "add",
				"path":  "/language",
				"value": "xyz",
			}},
			resource:   account,
			wantStatus: http.StatusOK,
		},
		{
			name:    "compartment restricted access denied to non compartment member",
			scopes:  "patient/Account.*",
			patient: otherPatient.id,
			patch: []map[string]interface{}{{
				"op":    "add",
				"path":  "/language",
				"value": "xyz",
			}},
			resource:   account,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{"Content-Type": "application/json-patch+json"}
			path := fmt.Sprintf("%s/fhir/%s/%s", c.storeName(), tc.resource.resType, tc.resource.id)

			resp := sendRequest(t, http.MethodPatch, path, tc.patch, headers, universalClaims(tc.scopes, tc.patient))
			if resp.StatusCode != tc.wantStatus {
				b, _ := ioutil.ReadAll(resp.Body)
				t.Errorf("fhir.patch got unexpected resp status=%d, want=%d; message=%s", resp.StatusCode, tc.wantStatus, string(b))
			}
		})
	}
}

func TestRead(t *testing.T) {
	c := setup(t)
	defer cleanup(t, c)

	tests := []struct {
		name       string
		scopes     string
		patient    string
		get        *resource
		wantStatus int
	}{
		{
			name:       "access granted",
			scopes:     "user/Patient.*",
			get:        rootPatient,
			wantStatus: http.StatusOK,
		},
		{
			name:       "access denied",
			scopes:     "user/Observation.* user/Patient.write",
			get:        rootPatient,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "compartment restricted access granted to compartment member",
			scopes:     "patient/Account.*",
			patient:    rootPatient.id,
			get:        account,
			wantStatus: http.StatusOK,
		},
		{
			name:       "compartment restricted access denied to non compartment member",
			scopes:     "patient/Account.*",
			patient:    otherPatient.id,
			get:        account,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "invalid headers - access denied",
			scopes:     "invalid/Scopes.*",
			get:        rootPatient,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "no headers - access denied",
			scopes:     "",
			get:        rootPatient,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "patient scope without pctx - access denied",
			scopes:     "patient/*.*",
			patient:    "",
			get:        rootPatient,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "system scope with pctx - access denied",
			scopes:     "system/*.*",
			patient:    rootPatient.id,
			get:        rootPatient,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := fmt.Sprintf("%s/fhir/%s/%s", c.storeName(), tc.get.resType, tc.get.id)

			resp := sendRequest(t, http.MethodGet, path, nil, nil, universalClaims(tc.scopes, tc.patient))
			if resp.StatusCode != tc.wantStatus {
				b, _ := ioutil.ReadAll(resp.Body)
				t.Errorf("fhir.get got unexpected resp status=%d, want=%d; message=%s", resp.StatusCode, tc.wantStatus, string(b))
			}
		})
	}
}

func TestDelete(t *testing.T) {
	c := setup(t)
	defer cleanup(t, c)

	tests := []struct {
		name       string
		scopes     string
		patient    string
		delete     *resource
		wantStatus int
	}{
		{
			name:       "access granted",
			scopes:     "user/Patient.*",
			delete:     otherPatient,
			wantStatus: http.StatusOK,
		},
		{
			name:       "access denied",
			scopes:     "user/Observation.* user/Observation.read",
			delete:     otherPatient,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "compartment restricted access granted to compartment member",
			scopes:     "patient/Account.*",
			patient:    rootPatient.id,
			delete:     account,
			wantStatus: http.StatusOK,
		},
		{
			name:       "compartment restricted access denied to non compartment member",
			scopes:     "patient/Account.*",
			patient:    otherPatient.id,
			delete:     account,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset store state to re-create any deleted resources.
			prepopulateStore(t, c.storeName())
			path := fmt.Sprintf("%s/fhir/%s/%s", c.storeName(), tc.delete.resType, tc.delete.id)

			resp := sendRequest(t, http.MethodDelete, path, nil, nil, universalClaims(tc.scopes, tc.patient))
			if resp.StatusCode != tc.wantStatus {
				b, _ := ioutil.ReadAll(resp.Body)
				t.Errorf("fhir.delete got unexpected resp status=%d, want=%d; message=%s", resp.StatusCode, tc.wantStatus, string(b))
			}
		})
	}
}

func TestPatientEverything(t *testing.T) {
	c := setup(t)
	defer cleanup(t, c)

	tests := []struct {
		name       string
		scopes     string
		patient    string
		getPatient *resource
		wantStatus int
	}{
		{
			name:       "access granted",
			scopes:     "user/*.*",
			getPatient: rootPatient,
			wantStatus: http.StatusOK,
		},
		{
			name:       "no read access to root patient - access denied",
			scopes:     "user/Observation.* user/Patient.write",
			getPatient: rootPatient,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "compartment restricted, patient ctx is root patient - access granted",
			scopes:     "patient/*.*",
			patient:    rootPatient.id,
			getPatient: rootPatient,
			wantStatus: http.StatusOK,
		},
		{
			name:       "compartment restricted, patient ctx is not root patient - access denied",
			scopes:     "patient/*.*",
			patient:    rootPatient.id,
			getPatient: otherPatient,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := fmt.Sprintf("%s/fhir/Patient/%s/$everything", c.storeName(), tc.getPatient.id)

			resp := sendRequest(t, http.MethodGet, path, nil, nil, universalClaims(tc.scopes, tc.patient))
			if resp.StatusCode != tc.wantStatus {
				b, _ := ioutil.ReadAll(resp.Body)
				t.Errorf("fhir.patient-everything got unexpected resp status=%d, want=%d; message=%s", resp.StatusCode, tc.wantStatus, string(b))
			}
		})
	}
}

func TestSearch(t *testing.T) {
	c := setup(t)
	defer cleanup(t, c)

	tests := []struct {
		name       string
		scopes     string
		patient    string
		query      string
		wantStatus int
	}{
		{
			name:       "access granted",
			scopes:     "user/*.*",
			query:      fmt.Sprintf("_id=%s", rootPatient.id),
			wantStatus: http.StatusOK,
		},
		{
			name:       "access denied - invalid headers",
			scopes:     "patient/Device.read",
			query:      fmt.Sprintf("_id=%s", rootPatient.id),
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "compartment restricted, access granted",
			scopes:     "patient/*.*",
			patient:    rootPatient.id,
			query:      fmt.Sprintf("_id=%s", rootPatient.id),
			wantStatus: http.StatusOK,
		},
		{
			name:       "compartment restricted, access denied - invalid headers",
			scopes:     "patient/Device.read",
			patient:    rootPatient.id,
			query:      fmt.Sprintf("_id=%s", rootPatient.id),
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := fmt.Sprintf("%s/fhir/Patient/?%s", c.storeName(), tc.query)

			resp := sendRequest(t, http.MethodGet, path, nil, nil, universalClaims(tc.scopes, tc.patient))
			if resp.StatusCode != tc.wantStatus {
				b, _ := ioutil.ReadAll(resp.Body)
				t.Errorf("fhir.search got unexpected resp status=%d, want=%d; message=%s", resp.StatusCode, tc.wantStatus, string(b))
			}
		})
	}
}

func TestExecuteBundle(t *testing.T) {
	c := setup(t)
	defer cleanup(t, c)

	tests := []struct {
		name       string
		scopes     string
		patient    string
		body       map[string]interface{}
		wantStatus int
	}{
		{
			name:   "access granted",
			scopes: "user/*.*",
			body: map[string]interface{}{
				"type":         "transaction",
				"resourceType": "Bundle",
				"entry": []map[string]interface{}{
					{
						"request": map[string]interface{}{
							"method": "DELETE",
							"url":    fmt.Sprintf("%s/%s", otherPatient.resType, otherPatient.id),
						},
					},
					{
						"request": map[string]interface{}{
							"method": "GET",
							"url":    fmt.Sprintf("%s/%s", rootPatient.resType, rootPatient.id),
						},
					},
				},
			},
			wantStatus: http.StatusOK,
		},
		{
			name:   "access denied",
			scopes: "user/Patient.write",
			body: map[string]interface{}{
				"type":         "transaction",
				"resourceType": "Bundle",
				"entry": []map[string]interface{}{
					{
						"request": map[string]interface{}{
							"method": "DELETE",
							"url":    fmt.Sprintf("%s/%s", otherPatient.resType, otherPatient.id),
						},
					},
					{
						"request": map[string]interface{}{
							"method": "GET",
							"url":    fmt.Sprintf("%s/%s", rootPatient.resType, rootPatient.id),
						},
					},
				},
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:    "compartment restricted access granted",
			scopes:  "user/*.*",
			patient: rootPatient.id,
			body: map[string]interface{}{
				"type":         "transaction",
				"resourceType": "Bundle",
				"entry": []map[string]interface{}{
					{
						"request": map[string]interface{}{
							"method": "DELETE",
							"url":    fmt.Sprintf("%s/%s", account.resType, account.id),
						},
					},
					{
						"request": map[string]interface{}{
							"method": "GET",
							"url":    fmt.Sprintf("%s/%s", rootPatient.resType, rootPatient.id),
						},
					},
				},
			},
			wantStatus: http.StatusOK,
		},
		{
			name:    "compartment restricted access denied",
			scopes:  "user/*.*",
			patient: otherPatient.id,
			body: map[string]interface{}{
				"type":         "transaction",
				"resourceType": "Bundle",
				"entry": []map[string]interface{}{
					{
						"request": map[string]interface{}{
							"method": "DELETE",
							"url":    fmt.Sprintf("%s/%s", account.resType, account.id),
						},
					},
					{
						"request": map[string]interface{}{
							"method": "GET",
							"url":    fmt.Sprintf("%s/%s", rootPatient.resType, rootPatient.id),
						},
					},
				},
			},
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset store state to re-create any deleted resources.
			prepopulateStore(t, c.storeName())
			headers := map[string]string{"Content-Type": "application/fhir+json;charset=utf-8"}
			path := fmt.Sprintf("%s/fhir", c.storeName())

			resp := sendRequest(t, http.MethodPost, path, tc.body, headers, universalClaims(tc.scopes, tc.patient))
			if resp.StatusCode != tc.wantStatus {
				b, _ := ioutil.ReadAll(resp.Body)
				t.Errorf("GetPatientEverything() got unexpected resp status=%d, want=%d; message=%s", resp.StatusCode, tc.wantStatus, string(b))
			}
		})
	}
}

func TestHistory(t *testing.T) {
	c := setup(t)
	defer cleanup(t, c)

	tests := []struct {
		name       string
		scopes     string
		patient    string
		get        *resource
		wantStatus int
	}{
		{
			name:       "access granted",
			scopes:     "user/Patient.*",
			get:        rootPatient,
			wantStatus: http.StatusOK,
		},
		{
			name:       "access denied",
			scopes:     "user/Observation.* user/Patient.write",
			get:        rootPatient,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "compartment restricted access granted to compartment member",
			scopes:     "patient/Account.*",
			patient:    rootPatient.id,
			get:        account,
			wantStatus: http.StatusOK,
		},
		{
			name:       "compartment restricted access denied to non compartment member",
			scopes:     "patient/Account.*",
			patient:    otherPatient.id,
			get:        account,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := fmt.Sprintf("%s/fhir/%s/%s/_history", c.storeName(), tc.get.resType, tc.get.id)

			resp := sendRequest(t, http.MethodGet, path, nil, nil, universalClaims(tc.scopes, tc.patient))
			if resp.StatusCode != tc.wantStatus {
				b, _ := ioutil.ReadAll(resp.Body)
				t.Errorf("fhir.history got unexpected resp status=%d, want=%d; message=%s", resp.StatusCode, tc.wantStatus, string(b))
			}
		})
	}
}

func TestUnimplementedMethod(t *testing.T) {
	c := setup(t)
	defer cleanup(t, c)

	path := fmt.Sprintf("%s/fhir/ConceptMap/$translate", c.storeName())

	resp := sendRequest(t, http.MethodGet, path, nil, nil, universalClaims("system/*.*", ""))
	if resp.StatusCode != http.StatusForbidden {
		b, _ := ioutil.ReadAll(resp.Body)
		t.Errorf("fhir.conceptmap-search-translate got unexpected resp status=%d, want=%d; message=%s", resp.StatusCode, http.StatusForbidden, string(b))
	}
}

func TestMain(m *testing.M) {
	if !flag.Parsed() {
		flag.Parse()
	}

	if !*enabled {
		glog.Info("E2E test skipped")
		os.Exit(0)
	}

	verifyArgs()

	os.Exit(m.Run())
}

func verifyArgs() {
	if len(*proxyURL) == 0 {
		glog.Fatalf("Arg 'proxy' is required")
	}
	if len(*chcEndpoint) == 0 {
		glog.Fatalf("Arg 'chc' is required")
	}
	if len(*project) == 0 {
		glog.Fatalf("Arg 'project' is required")
	}
	if len(*apiVersion) == 0 {
		glog.Fatalf("Arg 'apiVersion' is required")
	}
	if len(*location) == 0 {
		glog.Fatalf("Arg 'location' is required")
	}
}
