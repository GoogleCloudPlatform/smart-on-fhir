# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

terraform {
  required_version = "~> 0.12.0"
  required_providers {
    google      = "~> 3.0"
    google-beta = "~> 3.0"
  }
  backend "gcs" {
    bucket = "sof-test-terraform-state"
    prefix = "apps"
  }
}

# Reserve a static external IP for the Ingress.
resource "google_compute_global_address" "ingress_static_ip" {
  name         = "sof-ingress-ip"
  description  = "Reserved static external IP for the GKE cluster Ingress and DNS configurations."
  address_type = "EXTERNAL" # This is the default, but be explicit because it's important.
  project      = module.project.project_id
}

# Build Smart on FHIR proxy container.
resource "null_resource" "cloudbuild_image_builder" {
  provisioner "local-exec" {
    working_dir = "${path.module}/../.."
    command     = <<EOT
      gcloud builds submit . \
      --project ${module.project.project_id} \
      --config=proxy/deploy/cloudbuild/cloudbuild.yaml
  EOT
  }
}

module "sof_test_gke_cluster" {
  source  = "terraform-google-modules/kubernetes-engine/google//modules/beta-private-cluster-update-variant"
  version = "~> 12.0.0"

  # Required.
  name       = "sof-test-gke-cluster"
  project_id = module.project.project_id
  region     = "us-central1"
  regional   = true

  network_project_id      = "sof-test-networks"
  network                 = "sof-test-network"
  subnetwork              = "sof-test-gke-subnet"
  ip_range_pods           = "sof-test-pods-range"
  ip_range_services       = "sof-test-services-range"
  service_account         = "${google_service_account.sofuser.account_id}@sof-test-apps.iam.gserviceaccount.com"
  master_ipv4_cidr_block  = "192.168.0.0/28"
  istio                   = true
  skip_provisioners       = true
  enable_private_endpoint = false
  release_channel         = "STABLE"
  network_policy          = true
  # Removing the default node pull, as it cannot be modified without destroying the cluster.
  remove_default_node_pool = true
  # Basic Auth disabled
  basic_auth_username           = ""
  basic_auth_password           = ""
  issue_client_certificate      = false
  deploy_using_private_endpoint = true
  # Private nodes better control public exposure, and reduce the
  # ability of nodes to reach to the Internet without additional configurations.
  enable_private_nodes = true
  # Allow the cluster master to be accessible globally (from any region).
  master_global_access_enabled = true
  # master_authorized_networks can be specified to restrict access to the public endpoint.
  # Also see https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters.
  # TODO: add policies.
  enable_binary_authorization = true
  # Disable workload identity as using a single Compute Engine SA is sufficient.
  identity_namespace = null
  # Expose GCE metadata to pods.
  node_metadata = "EXPOSE"
}

# Create the project and optionally enable APIs, create the deletion lien and add to shared VPC.
# Deletion lien: https://cloud.google.com/resource-manager/docs/project-liens
# Shared VPC: https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#centralize_network_control
module "project" {
  source  = "terraform-google-modules/project-factory/google//modules/shared_vpc"
  version = "~> 9.2.0"

  name                    = "sof-test-apps"
  org_id                  = ""
  folder_id               = "000000000000"
  billing_account         = "XXXXXX-XXXXXX-XXXXXX"
  lien                    = true
  default_service_account = "keep"
  skip_gcloud_download    = true
  shared_vpc              = "sof-test-networks"
  shared_vpc_subnets = [
    "projects/sof-test-networks/regions/us-central1/subnetworks/sof-test-gke-subnet",
  ]
  activate_apis = [
    "iam.googleapis.com",
    "healthcare.googleapis.com",
    "cloudbuild.googleapis.com",
    "containerregistry.googleapis.com",
    "container.googleapis.com",
    "compute.googleapis.com",
  ]
}

module "project_iam_members" {
  source  = "terraform-google-modules/iam/google//modules/projects_iam"
  version = "~> 6.3.0"

  projects = [module.project.project_id]
  mode     = "additive"

  bindings = {
    "roles/healthcare.datasetAdmin" = [
      "serviceAccount:${google_service_account.fhiruser.account_id}@sof-test-apps.iam.gserviceaccount.com",
    ],
    "roles/healthcare.datasetViewer" = [
      "serviceAccount:${google_service_account.fhiruser.account_id}@sof-test-apps.iam.gserviceaccount.com",
    ],
    "roles/healthcare.fhirResourceEditor" = [
      "serviceAccount:${google_service_account.fhiruser.account_id}@sof-test-apps.iam.gserviceaccount.com",
    ],
    "roles/healthcare.fhirStoreAdmin" = [
      "serviceAccount:${google_service_account.fhiruser.account_id}@sof-test-apps.iam.gserviceaccount.com",
    ],
    "roles/iam.serviceAccountTokenCreator" = [
      "serviceAccount:${google_service_account.sofuser.account_id}@sof-test-apps.iam.gserviceaccount.com",
    ],
    "roles/logging.logWriter" = [
      "serviceAccount:${google_service_account.sofuser.account_id}@sof-test-apps.iam.gserviceaccount.com",
    ],
    "roles/monitoring.metricWriter" = [
      "serviceAccount:${google_service_account.sofuser.account_id}@sof-test-apps.iam.gserviceaccount.com",
    ],
    "roles/monitoring.viewer" = [
      "serviceAccount:${google_service_account.sofuser.account_id}@sof-test-apps.iam.gserviceaccount.com",
    ],
    "roles/storage.objectViewer" = [
      "serviceAccount:${google_service_account.sofuser.account_id}@sof-test-apps.iam.gserviceaccount.com",
    ],
  }
}

resource "google_service_account" "sofuser" {
  account_id   = "sofuser"
  display_name = "sofuser"

  description = "Used to run smart on FHIR proxy"

  project = module.project.project_id
}

resource "google_service_account" "fhiruser" {
  account_id   = "fhiruser"
  display_name = "fhiruser"

  description = "Used to access FHIR API"

  project = module.project.project_id
}
