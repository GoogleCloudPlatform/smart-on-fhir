# Deploy SMART on FHIR proxy using Terraform Engine and Terraform

This document provides instructions for deploying the SMART on FHIR proxy on
Google Cloud Platform (GCP) using infrastructure-as-code.

The provided [template](./deployment.hcl) can be instantiated and used with the
[Terraform Engine](https://github.com/GoogleCloudPlatform/healthcare-data-protection-suite/tree/master/docs/tfengine)
to generate Terraform configs that define and deploy the entire infrastructure.

The generated Terraform configs from the template deploy the SMART on FHIR
proxy infrastructure in a dedicated GCP folder with remote Terraform state
management and CICD pipelines enabled by default. The generated Terraform
configs should also be checked in to this GitHub repository, e.g. in
`deploy_generated` directory.

This Terraform deployment is an adaptation of Google Cloud's
[HIPAA-aligned architecture](https://cloud.google.com/solutions/architecture-hipaa-aligned-project).
This approach to project configuration and deployment is explained in the
["Setting up a HIPAA-aligned project"](https://cloud.google.com/solutions/setting-up-a-hipaa-aligned-project)
solution guide. Google Cloud's
[best practices for enterprise organizations](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations)
are also followed.

## Prerequisites

Follow
[Prerequisites](https://github.com/GoogleCloudPlatform/healthcare-data-protection-suite/tree/master/docs/tfengine#prerequisites)
and prepare to deploy the infrastructure in a folder.

## Installation

Follow the
[installation instructions](https://github.com/GoogleCloudPlatform/healthcare-data-protection-suite/tree/master/docs/tfengine/#installation)
to install the tfengine binary v0.4.0.

## Layout of the generated configs

```bash
|- devops/:     one time manual deployment to create projects to host Terraform state
                and CICD pipelines.
|- cicd/:       one time manual deployment to create CICD pipelines and
                configure permissions.
|- audit/:      audit project and resources (logs bucket, dataset and sinks).
|- networks/:   apps project and resources (VPC, NAT).
|- apps/:       networks project and resources (GKE, Service Accounts).
|- kubernetes/: kubernetes deployment configs for after the GKE cluster has been created.
```

Each directory except `kubernetes/` represents one Terraform deployment. Each
deployment will manage specific resources in you infrastructure.

A deployment typically contains the following files:

- **main.tf**: This file defines the Terraform resources and modules to
    manage.

- **variables.tf**: This file defines any input variables that the deployment
    can take.

- **outputs.tf**: This file defines any outputs from this deployment. These
    values can be used by other deployments.

- **terraform.tfvars**: This file defines values for the input variables.

To see what resources each deployment provisions, check out the comments in both
the [deployment.hcl](./deployment.hcl) file and individual **main.tf** files.

## CICD

Deployments listed under `managed_modules` in the `cicd` recipe are configured
to be deployed via CICD pipelines.

The CICD service account can manage a subset of resources (e.g. APIs) within its
own project (`devops` project). This allows users to have low risk changes made
in the `devops` project deployed through standard Cloud Build pipelines,
without needing to apply it manually. Other changes in the `devops` project
outside the approved set (APIs) will still need to be made manually.

A common use case for this is when adding a new resource in a project that
requires a new API to be enabled. You must add the API in both the resource's
project as well as the `devops` project. With the feature above, the CICD can
deploy both changes for you.

## Deployment steps

Note that the deployment steps involve editing the Terraform Engine config and
regenerating the Terraform configs several times.

### Preparation

1. Authenticate as a super admin using `gcloud auth login [ACCOUNT]`.

    WARNING: remember to run `gcloud auth revoke` to logout as a super admin.
    Being logged in as a super admin beyond the initial setup is dangerous!

1. Make a copy of [deployment.hcl](./deployment.hcl) and fill in instance
    specific values, which includes:

    - prefix
    - env
    - oidc_issuer
    - aud
    - billing_account
    - parent_id
    - github.owner
    - github.name
    - ...

    You can also change other field such as location of resources, etc to fit
    your use case.

1. Clone the remote GitHub repository locally which will be used to check in
    your Terraform configs and save the local path to an environment variable
    `GIT_ROOT`.

    ```bash
    export GIT_ROOT=/path/to/your/local/repo/smart-on-fhir
    ```

1. Save the path to your copy of the template to an environment variable
    `ENGINE_CONFIG`.

    ```bash
    export ENGINE_CONFIG=$GIT_ROOT/deployment.hcl
    ```

### Step 1: Terraform deployment of the Devops project and CICD manually

1. Execute the `tfengine` command to generate the configs. By default, CICD
    will look for Terraform configs under the `deploy_generated/` directory in
    the GitHub repo, so set the `--output_path` to point to the
    `deploy_generated/` directory inside the local root of your GitHub
    repository.

    Make sure in your first deployment in a new folder, `enable_gcs_backend` in
    $ENGINE_CONFIG is set to `false` or commented out.

    ```bash
    tfengine --config_path=$ENGINE_CONFIG --output_path=$GIT_ROOT/deploy_generated
    ```

#### Devops Project

1. Deploy the `devops/` folder first to create the `devops` project and
    Terraform state bucket.

    ```bash
    cd $GIT_ROOT/deploy_generated/devops
    terraform init
    terraform apply
    ```

    Your `devops` project should now be ready.

1. In $ENGINE_CONFIG, set `enable_gcs_backend` to `true`, and regenerate the
    Teraform configs.

    ```bash
    tfengine --config_path=$ENGINE_CONFIG --output_path=$GIT_ROOT/deploy_generated
    ```

1. Backup the state of the `devops` project to the newly created state bucket
    by running the following command.

    ```bash
    terraform init -force-copy
    ```

#### CICD pipelines

1. Install the Cloud Build app and
    [connect your GitHub repository](https://console.cloud.google.com/cloud-build/triggers/connect)
    to {PREFIX}-{ENV}-devops project by following the steps in
    [Installing the Cloud Build app](https://cloud.google.com/cloud-build/docs/automating-builds/create-github-app-triggers#installing_the_cloud_build_app).

    To perform this operation, you need Admin permission in that GitHub
    repository.

1. Deploy the `cicd/` folder to set up CICD pipelines.

    ```bash
    cd $GIT_ROOT/deploy_generated/cicd
    terraform init
    terraform apply
    ```

### Step 2: Terraform deployment of resources through CICD

1. Add the following items to your `.gitignore` file to avoid accidentally
    committing any `.terraform/` directories, `*.tfstate` or `*.tfstate.backup`
    files generated from previous manual deployments:

    ```bash
    **/.terraform
    *.tfstate
    *.tfstate.*
    ```

1. Commit your current local git working dir and send a Pull Request to merge
    these configs. Make sure the presubmit tests pass and get code review
    approvals. The CD job will then deploy the rest of Terraform resources for
    you.

    - Audit
        - Project, log sink bucket and dataset
    - Networks
        - Project, VPC, NAT
    - Apps
        - Project, Service Accounts, GKE

### Step 3: Kubernetes deployment manually

1. Deploy the GKE resources by executing the following commands:

    ```bash
    cd $GIT_ROOT
    # Value of {default_location} comes from deployment.hcl.
    gcloud container clusters get-credentials {PREFIX}-{ENV}-gke-cluster \
      --region {default_location} --project={PREFIX}-{ENV}-apps
    kubectl apply -f deploy_generated/kubernetes/k8s.yaml
    kubectl apply -f deploy_generated/kubernetes/ingress.yaml
    ```

    The service might take 10 min to start.

    The deployment is now complete.

### Step 4: Clean up

1. Revoke your super admin access by running `gcloud auth revoke` and
    authenticate as a normal user for daily activities.
