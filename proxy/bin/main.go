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

// Package main run the binary of the smart on fhir reverse proxy
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"

	"cloud.google.com/go/logging" /* copybara-comment: logging */
	"cloud.google.com/go/secretmanager/apiv1" /* copybara-comment: secretmanager */
	"google.golang.org/api/option" /* copybara-comment: option */
	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/cache" /* copybara-comment: cache */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/cache/rediz" /* copybara-comment: rediz */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/osenv" /* copybara-comment: osenv */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/secret" /* copybara-comment: secret */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/server" /* copybara-comment: server */
	"github.com/GoogleCloudPlatform/smart-on-fhir/proxy/lib/proxy" /* copybara-comment: proxy */

	glog "github.com/golang/glog" /* copybara-comment */
	iamcreds "cloud.google.com/go/iam/credentials/apiv1" /* copybara-comment: credentials */
	grpcbackoff "google.golang.org/grpc/backoff" /* copybara-comment */
)

var (
	port      = osenv.VarWithDefault("PORT", "8080")
	project   = osenv.MustVar("PROXY_PROJECT")
	redisAddr = os.Getenv("CACHE_ADDR")
)

func main() {
	flag.Parse()

	opts := proxy.ReadOptionsFromEnv()

	ctx := context.Background()
	logger, err := logging.NewClient(ctx, project)
	if err != nil {
		glog.Exitf("logging.NewClient() failed: %v", err)
	}
	logger.OnError = func(err error) {
		glog.Warningf("StackdriverLogging.Client.OnError: %v", err)
	}

	iamClient, err := iamcreds.NewIamCredentialsClient(ctx, option.WithGRPCDialOption(grpc.WithConnectParams(grpc.ConnectParams{Backoff: grpcbackoff.DefaultConfig})))
	if err != nil {
		glog.Fatalf("iamcreds.NewIamCredentialsClient() failed: %v", err)
	}

	secretmanagerClient, err := secretmanager.NewClient(ctx)
	if err != nil {
		glog.Fatalf("failed to create secretmanager client: %v", err)
	}

	secretClient := secret.New(secretmanagerClient, project)

	var cacheClient func() cache.Client
	if len(redisAddr) > 0 {
		pool := rediz.NewPool(redisAddr)
		cacheClient = func() cache.Client { return pool.Client() }
	}

	r := mux.NewRouter()
	r.HandleFunc("/liveness_check", httputils.LivenessCheckHandler)

	if _, err := proxy.New(ctx, r, opts, logger, iamClient, secretClient, cacheClient); err != nil {
		glog.Fatalf("proxy.New() failed: %v", err)
	}

	srv := server.New("fhirproxy", port, r)
	srv.ServeUnblock()

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(c, os.Interrupt)

	// Block until we receive our signal.
	<-c

	srv.Shutdown()
}
