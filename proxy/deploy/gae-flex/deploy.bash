#!/bin/bash

# Copyright 2020 Google LLC.
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

GREEN="\e[32m"
RED="\e[31m"
RESET="\e[0m"

PROJECT=${PROJECT}

print_usage() {
  echo -e ${RED?}'Usage: prepare_project [-h] [-p project_id] [-a aud] [-o oidc_issuer]'${RESET?}
  echo -e ${RED?}'  -h \t show this help usage'${RESET?}
  echo -e ${RED?}'  -p \t GCP project_id to deploy to'${RESET?}
  echo -e ${RED?}'  -a \t expected audience in token'${RESET?}
  echo -e ${RED?}'  -o \t oidc issuer to verify the token'${RESET?}
}

while getopts ':hp:a:o:' flag; do
  case "${flag}" in
    h) print_usage
       exit 1 ;;
    p) PROJECT="${OPTARG}" ;;
    o) OIDC_ISSUER="${OPTARG}" ;;
    a) AUD="${OPTARG}" ;;
    *) echo -e ${RED?}'Unknown flag: -'${flag}${RESET?}
       print_usage
       exit 1 ;;
  esac
done

# run test
echo -e ${GREEN?}'Run tests'${RESET?}
./runtest.bash
if [[ $? -ne 0 ]]; then
  echo -e "${RED?}Run tests failed${RESET?}"
  exit $?
fi

# use cloudbuild to build to docker image
echo -e ${GREEN?}'Build image'${RESET?}
gcloud builds submit --project=${PROJECT?} --config proxy/deploy/cloudbuild/cloudbuild.yaml .

# Replace vars in GAE yaml
cp proxy/deploy/gae-flex/fhirproxy.template.yaml proxy/deploy/gae-flex/fhirproxy.yaml

sed -i 's#${YOUR_PROJECT_ID}#'${PROJECT?}'#g' ./proxy/deploy/gae-flex/fhirproxy.yaml
sed -i 's#${OIDC_ISSUER}#'${OIDC_ISSUER?}'#g' ./proxy/deploy/gae-flex/fhirproxy.yaml
sed -i 's#${AUD}#'${AUD?}'#g' ./proxy/deploy/gae-flex/fhirproxy.yaml

# start GAE Flex service
echo -e ${GREEN?}'Start GAE Flex service'${RESET?}
gcloud beta -q --project=${PROJECT?} app deploy proxy/deploy/gae-flex/fhirproxy.yaml --image-url=gcr.io/${PROJECT?}/fhirproxy:latest --version=master

rm proxy/deploy/gae-flex/fhirproxy.yaml
