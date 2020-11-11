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
    prefix = "networks"
  }
}

resource "google_compute_firewall" "fw_allow_k8s_ingress_lb_health_checks" {
  name        = "fw-allow-k8s-ingress-lb-health-checks"
  description = "GCE L7 firewall rule"
  network     = module.sof_test_network.network.network.self_link
  project     = module.project.project_id

  allow {
    protocol = "tcp"
    ports    = ["30000-32767"]
  }

  # Load Balancer Health Check IP ranges.
  source_ranges = [
    "130.211.0.0/22",
    "209.85.152.0/22",
    "209.85.204.0/22",
    "35.191.0.0/16",
  ]

  # This Service Account will later be created in the apps project and associated
  # with the GKE cluster. Firewall rule creation accepts a non-existing target
  # service account.
  target_service_accounts = [
    "sofuser@sof-test-apps.iam.gserviceaccount.com"
  ]
}


# Create the project and optionally enable APIs, create the deletion lien and add to shared VPC.
# Deletion lien: https://cloud.google.com/resource-manager/docs/project-liens
# Shared VPC: https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#centralize_network_control
module "project" {
  source  = "terraform-google-modules/project-factory/google"
  version = "~> 9.2.0"

  name                           = "sof-test-networks"
  org_id                         = ""
  folder_id                      = "000000000000"
  billing_account                = "XXXXXX-XXXXXX-XXXXXX"
  lien                           = true
  default_service_account        = "keep"
  skip_gcloud_download           = true
  enable_shared_vpc_host_project = true
  activate_apis = [
    "container.googleapis.com",
    "compute.googleapis.com",
    "servicenetworking.googleapis.com",
  ]
}

module "sof_test_network" {
  source  = "terraform-google-modules/network/google"
  version = "~> 2.5.0"

  network_name = "sof-test-network"
  project_id   = module.project.project_id

  subnets = [
    {
      subnet_name           = "sof-test-gke-subnet"
      subnet_ip             = "10.0.0.0/17"
      subnet_region         = "us-central1"
      subnet_flow_logs      = true
      subnet_private_access = true
    },

  ]
  secondary_ranges = {
    "sof-test-gke-subnet" = [
      {
        range_name    = "sof-test-pods-range"
        ip_cidr_range = "172.16.0.0/14"
      },
      {
        range_name    = "sof-test-services-range"
        ip_cidr_range = "172.20.0.0/20"
      },
    ],
  }
}


module "sof_test_router" {
  source  = "terraform-google-modules/cloud-router/google"
  version = "~> 0.2.0"

  name    = "sof-test-router"
  project = module.project.project_id
  region  = "us-central1"
  network = module.sof_test_network.network.network.self_link

  nats = [
    {
      name                               = "sof-test-nat"
      source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

      subnetworks = [
        {
          name                     = "${module.sof_test_network.subnets["us-central1/sof-test-gke-subnet"].self_link}"
          source_ip_ranges_to_nat  = ["ALL_IP_RANGES"]
          secondary_ip_range_names = []
        },
      ]
    },
  ]
}
