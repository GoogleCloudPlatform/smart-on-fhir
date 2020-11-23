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

# {{$recipes := "git://github.com/GoogleCloudPlatform/healthcare-data-protection-suite//templates/tfengine/recipes"}}
# {{$ref := "ref=templates-v0.5.0"}}

# {{$prefix := "sof"}}
# {{$env := "test"}}
# {{$domain := "example.com"}}
# {{$default_location := "us-central1"}}
# {{$default_zone := "a"}}
# OIDC issuer to verify the token.
# {{$oidc_issuer := "oidc_issue_url_placeholder"}}
# Expected audience in token.
# {{$audience := "audience_url_placeholder"}}

###########################
# Optional feature flags
###########################

# Enable if proxy want to accept opaque token
# {{$use_userinfo_to_verify_accesstoken := false}}
# Change to true if you want to enable caching opaque token.
# {{$enable_cache := false}}
# Change to true if you want to use secretmanager to store secret.
# {{$use_secret_manager := false}}
# Change to ture if you are setting up a e2e test project.
# {{$setup_e2e_test_project := false}}

data = {
  parent_type     = "folder"
  parent_id       = "000000000000"
  billing_account = "XXXXXX-XXXXXX-XXXXXX"
  state_bucket    = "{{$prefix}}-{{$env}}-terraform-state"

  # Default locations for resources. Can be overridden in individual templates.
  bigquery_location   = "us-east1" # BigQuery is not available in "us-central1"
  compute_region      = "{{$default_location}}"
  gke_region          = "{{$default_location}}"
  storage_location    = "{{$default_location}}"
}

# Central devops project for Terraform state management and CI/CD.
template "devops" {
  recipe_path = "{{$recipes}}/devops.hcl?{{$ref}}"
  output_path = "./devops"
  data = {
    # During Step 1, set to `true` and re-run the engine after generated devops module has been deployed.
    # Run `terraform init` in the devops module to backup its state to GCS.
    enable_gcs_backend = false

    admins_group = "{{$prefix}}-{{$env}}-folder-admins@{{$domain}}"

    project = {
      project_id = "{{$prefix}}-{{$env}}-devops"
      owners = [
        "group:{{$prefix}}-{{$env}}-devops-owners@{{$domain}}",
      ]
      apis = [
        "container.googleapis.com",
        "healthcare.googleapis.com",
        "cloudbuild.googleapis.com",
        "containerregistry.googleapis.com",
        "compute.googleapis.com",
        {{if $use_secret_manager}}
          "secretmanager.googleapis.com",
        {{end}}
        {{if $enable_cache}}
          "redis.googleapis.com",
        {{end}}
      ]
    }
  }
}

template "cicd" {
  recipe_path = "{{$recipes}}/cicd.hcl?{{$ref}}"
  output_path = "./cicd"
  data = {
    project_id = "{{$prefix}}-{{$env}}-devops"
    github = {
      owner = "GoogleCloudPlatform"
      name  = "example"
    }
    branch_name    = "main"
    terraform_root = "deploy_generated"

    # Prepare and enable default triggers.
    triggers = {
      validate = {}
      plan     = {}
      apply    = {}
    }

    # IAM members to give the roles/cloudbuild.builds.viewer permission so they can see build results.
    build_viewers = [
      "group:{{$prefix}}-{{$env}}-cicd-viewers@{{$domain}}",
    ]

    managed_dirs = [
      "devops", // NOTE: CICD service account can only update APIs on the devops project.
      "audit",
      "networks",
      "apps",
    ]
  }
}

template "audit" {
  recipe_path = "{{$recipes}}/audit.hcl?{{$ref}}"
  output_path = "./audit"
  data = {
    auditors_group = "{{$prefix}}-{{$env}}-auditors@{{$domain}}"
    project = {
      project_id = "{{$prefix}}-{{$env}}-audit"
    }
    logs_bigquery_dataset = {
      dataset_id = "{{$prefix}}_{{$env}}_1yr_audit_logs"
    }
    logs_storage_bucket = {
      name = "{{$prefix}}-{{$env}}-7yr-audit-logs"
    }
  }
}

# Central networks host project and resources.
template "project_networks" {
  recipe_path = "{{$recipes}}/project.hcl?{{$ref}}"
  output_path = "./networks"
  data = {
    project = {
      project_id         = "{{$prefix}}-{{$env}}-networks"
      apis = [
        "container.googleapis.com",
        "compute.googleapis.com",
        "servicenetworking.googleapis.com",
      ]
      is_shared_vpc_host = true
    }
    resources = {
      compute_networks = [{
        name = "{{$prefix}}-{{$env}}-network"
        subnets = [
          {
            name = "{{$prefix}}-{{$env}}-gke-subnet"
            # 10.0.0.0 --> 10.0.127.255
            ip_range = "10.0.0.0/17"
            secondary_ranges = [
              {
                name     = "{{$prefix}}-{{$env}}-pods-range"
                # /14 is the default size for the subnet's secondary IP range for Pods.
                # 172.16.0.0 --> 172.19.255.255
                ip_range = "172.16.0.0/14"
              },
              {
                name     = "{{$prefix}}-{{$env}}-services-range"
                # /20 is the default size for the subnet's secondary IP address range for Services.
                # 172.20.0.0 --> 172.20.15.255
                ip_range = "172.20.0.0/20"
              }
            ]
          },
        ]
      }]
      compute_routers = [{
        name    = "{{$prefix}}-{{$env}}-router"
        network = "$${module.{{$prefix}}_{{$env}}_network.network.network.self_link}"
        nats = [{
          name                               = "{{$prefix}}-{{$env}}-nat"
          source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"
          subnetworks = [
            {
              name                     = "$${module.{{$prefix}}_{{$env}}_network.subnets[\"{{$default_location}}/{{$prefix}}-{{$env}}-gke-subnet\"].self_link}"
              source_ip_ranges_to_nat  = ["ALL_IP_RANGES"]
              secondary_ip_range_names = []
            },
          ]
        }]
      }]
    }
    terraform_addons = {
      raw_config = <<EOF
resource "google_compute_firewall" "fw_allow_k8s_ingress_lb_health_checks" {
  name        = "fw-allow-k8s-ingress-lb-health-checks"
  description = "GCE L7 firewall rule"
  network     = module.{{$prefix}}_{{$env}}_network.network.network.self_link
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
    "sofuser@{{$prefix}}-{{$env}}-apps.iam.gserviceaccount.com"
  ]
}

{{if $enable_cache -}}
# Create IPs for redis.
resource "google_compute_global_address" "redis_private_ip_alloc" {
  name          = "redis-ip"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = module.{{$prefix}}_{{$env}}_network.network.network.id
  project       = module.project.project_id
}

resource "google_service_networking_connection" "redis_service_connect" {
  network                 = module.{{$prefix}}_{{$env}}_network.network.network.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.redis_private_ip_alloc.name]
}
{{end -}}
EOF
    }
  }
}

# Apps project and resources.
template "project_apps" {
  recipe_path = "{{$recipes}}/project.hcl?{{$ref}}"
  output_path = "./apps"
  data = {
    project = {
      project_id = "{{$prefix}}-{{$env}}-apps"
      apis = [
        "iam.googleapis.com",
        "healthcare.googleapis.com",
        "cloudbuild.googleapis.com",
        "containerregistry.googleapis.com",
        "container.googleapis.com",
        "compute.googleapis.com",
        {{if $use_secret_manager}}
        "secretmanager.googleapis.com",
        {{end}}
        {{if $enable_cache}}
        "redis.googleapis.com",
        {{end}}
      ]
      shared_vpc_attachment = {
        host_project_id = "{{$prefix}}-{{$env}}-networks"
        subnets = [{
          name = "{{$prefix}}-{{$env}}-gke-subnet"
        }]
      }
    }
    resources = {
      # Terraform-generated service account for use by the GKE apps.
      service_accounts = [
        # used to run smart on fhir proxy
        {
          account_id   = "sofuser"
          display_name = "sofuser"
          description  = "Used to run smart on FHIR proxy"
        },
        # used to access fhir API
        {
          account_id   = "fhiruser"
          display_name = "fhiruser"
          description  = "Used to access FHIR API"
        },
        {{if $setup_e2e_test_project}}
        # used to run test. Uncomment for project used to run E2E test.
        {
          account_id   = "testuser"
          display_name = "testuser"
          description  = "Used to run E2E test"
        },
        {{end}}
      ]
      iam_members = {
        "roles/monitoring.metricWriter" = [
          "serviceAccount:$${google_service_account.sofuser.account_id}@{{$prefix}}-{{$env}}-apps.iam.gserviceaccount.com",
        ]
        "roles/monitoring.viewer" = [
          "serviceAccount:$${google_service_account.sofuser.account_id}@{{$prefix}}-{{$env}}-apps.iam.gserviceaccount.com",
        ]
        "roles/logging.logWriter" = [
          "serviceAccount:$${google_service_account.sofuser.account_id}@{{$prefix}}-{{$env}}-apps.iam.gserviceaccount.com",
        ]
        "roles/storage.objectViewer" = [
          "serviceAccount:$${google_service_account.sofuser.account_id}@{{$prefix}}-{{$env}}-apps.iam.gserviceaccount.com",
        ]
        "roles/iam.serviceAccountTokenCreator" = [
          "serviceAccount:$${google_service_account.sofuser.account_id}@{{$prefix}}-{{$env}}-apps.iam.gserviceaccount.com",
        ]
        {{if $use_secret_manager}}
        "roles/secretmanager.viewer" = [
          "serviceAccount:$${google_service_account.sofuser.account_id}@{{$prefix}}-{{$env}}-apps.iam.gserviceaccount.com",
        ]
        {{end}}
        {{if $enable_cache}}
        "roles/redis.editor" = [
          "serviceAccount:$${google_service_account.sofuser.account_id}@{{$prefix}}-{{$env}}-apps.iam.gserviceaccount.com",
        ]
        {{end}}
        "roles/healthcare.datasetViewer" = [
          {{if $setup_e2e_test_project}}
          "serviceAccount:$${google_service_account.testuser.account_id}@{{$prefix}}-{{$env}}-apps.iam.gserviceaccount.com",
          {{end}}
        ]
        "roles/healthcare.datasetAdmin" = [
          {{if $setup_e2e_test_project}}
          "serviceAccount:$${google_service_account.testuser.account_id}@{{$prefix}}-{{$env}}-apps.iam.gserviceaccount.com",
          {{end}}
        ]
        "roles/healthcare.fhirStoreAdmin" = [
          {{if $setup_e2e_test_project}}
          "serviceAccount:$${google_service_account.testuser.account_id}@{{$prefix}}-{{$env}}-apps.iam.gserviceaccount.com",
          {{end}}
        ]
        "roles/healthcare.fhirResourceEditor" = [
          "serviceAccount:$${google_service_account.fhiruser.account_id}@{{$prefix}}-{{$env}}-apps.iam.gserviceaccount.com",
          {{if $setup_e2e_test_project}}
          "serviceAccount:$${google_service_account.testuser.account_id}@{{$prefix}}-{{$env}}-apps.iam.gserviceaccount.com",
          {{end}}
        ]
      }
    }
    terraform_addons = {
      outputs = [
        {
          name = "external_ip"
          value = "External ip of GKE ingress: $${google_compute_global_address.ingress_static_ip.address}"
        }
      ]
      raw_config = <<EOF
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
    working_dir = "$${path.module}/../.."
    command = <<EOT
      gcloud builds submit . \
      --project $${module.project.project_id} \
      --config=proxy/deploy/cloudbuild/cloudbuild.yaml
  EOT
  }
}

{{if $enable_cache -}}
# Use cache to improve opaque token validation performance.
module "memorystore" {
  source  = "terraform-google-modules/memorystore/google"
  version = "1.3.0"

  name               = "{{$prefix}}-{{$env}}-redis"
  project            = module.project.project_id
  region             = "{{$default_location}}"
  authorized_network = "projects/{{$prefix}}-{{$env}}-networks/global/networks/{{$prefix}}-{{$env}}-network"
  memory_size_gb     = 1
  connect_mode       = "PRIVATE_SERVICE_ACCESS"
}

# Update REDIS IP in k8s yaml.
resource "null_resource" "update_ip_in_k8s_yaml" {
  depends_on = [module.memorystore]

  provisioner "local-exec" {
    working_dir = "$${path.module}/../kubernetes"
    command = <<EOT
      sed -i 's/{REDIS_IP}/$${module.memorystore.host}/g' ./k8s.yaml
  EOT
  }
}
{{end -}}

module "{{$prefix}}_{{$env}}_gke_cluster" {
  source  = "terraform-google-modules/kubernetes-engine/google//modules/beta-private-cluster-update-variant"
  version = "~> 12.0.0"

  # Required.
  name       = "{{$prefix}}-{{$env}}-gke-cluster"
  project_id = module.project.project_id
  region     = "{{$default_location}}"
  regional   = true

  network_project_id       = "{{$prefix}}-{{$env}}-networks"
  network                  = "{{$prefix}}-{{$env}}-network"
  subnetwork               = "{{$prefix}}-{{$env}}-gke-subnet"
  ip_range_pods            = "{{$prefix}}-{{$env}}-pods-range"
  ip_range_services        = "{{$prefix}}-{{$env}}-services-range"
  service_account          = "$${google_service_account.sofuser.account_id}@{{$prefix}}-{{$env}}-apps.iam.gserviceaccount.com"
  master_ipv4_cidr_block   = "192.168.0.0/28"
  istio                    = true
  skip_provisioners        = true
  enable_private_endpoint  = false
  release_channel          = "STABLE"
  network_policy           = true
  # Removing the default node pull, as it cannot be modified without destroying the cluster.
  remove_default_node_pool = true
  # Basic Auth disabled
  basic_auth_username           = ""
  basic_auth_password           = ""
  issue_client_certificate      = false
  deploy_using_private_endpoint = true
  # Private nodes better control public exposure, and reduce the
  # ability of nodes to reach to the Internet without additional configurations.
  enable_private_nodes          = true
  # Allow the cluster master to be accessible globally (from any region).
  master_global_access_enabled  = true
  # master_authorized_networks can be specified to restrict access to the public endpoint.
  # Also see https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters.
  # TODO: add policies.
  enable_binary_authorization   = true
  # Disable workload identity as using a single Compute Engine SA is sufficient.
  identity_namespace            = null
  # Expose GCE metadata to pods.
  node_metadata                 = "EXPOSE"
}
EOF
    }
  }
}

template "k8s_configs" {
  component_path = "./proxy/deploy/gke/"
  output_path    = "./kubernetes"
  data = {
    project_id     = "{{$prefix}}-{{$env}}-apps"
    global_ip_name = "sof-ingress-ip"
    oidc_issuer    = "{{$oidc_issuer}}"
    audience       = "{{$audience}}"

    use_userinfo_to_verify_accesstoken = "{{$use_userinfo_to_verify_accesstoken}}"
    {{if $enable_cache}}
    cache_addr = "{REDIS_IP}:6379"
    {{else}}
    cache_addr = "\"\""
    {{end}}
    use_secret_manager = "{{$use_secret_manager}}"
  }
}
