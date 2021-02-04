# Deploy test persona server

A persona server allows you to mint SMART-on-FHIR tokens to simulate various users of the system. Available test users are set up via a configuration file as detailed below.

**IMPORTANT: only set up SMART-on-FHIR proxies to trust persona servers on synthetic or public data that contains no PHI.***

To set up a persona server as an OIDC Identity Provider for testing SMART-on-FHIR access, you will need to perform the following steps:

1. Setup a GCP project for persona server:

  ```
  ./scripts/prepare_persona_project.bash -p ${PROJECT_ID?}
  ```

1. Download the [healthcare-federated-access-services](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services) repo in any path.

  ```
  git clone https://github.com/GoogleCloudPlatform/healthcare-federated-access-services.git
  ```

1. Copy persona config to federated-access:

  ```
  cp -R testdata/config/personas /path/to/federated-access/deploy/config
  ```

  You can modify users or claims in `config_master_main_latest.json` for your testing setup.

1. Add env for persona service:

  ```
  cd /path/to/federated-access
  echo '  LOCAL_SIGNER_ALGORITHM: "RS384"' >> deploy/build-templates/personas/personas.yaml
  echo '  DAM_SERVICE_NAME: "personas"' >> deploy/build-templates/personas/personas.yaml
  ```

1. Deploy to GAE:

  ```
  ./deploy.bash -p ${PROJECT_ID?} -e test personas
  ```

1. Verify the deployment:

  ```
  curl https://personas-test-dot-${PROJECT_ID?}.uc.r.appspot.com/oidc/token?code=undergrad_candice
  ```

1. You will need the value of "iss" in JWT token to setup the Smart on FHIR proxy. See the [README.md](./README.md) for more details.
