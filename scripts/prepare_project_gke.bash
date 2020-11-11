#!/bin/bash

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

GREEN="\e[32m"
RED="\e[31m"
RESET="\e[0m"

PROJECT=${PROJECT}

print_usage() {
  echo -e ${RED?}'Usage: prepare_internal_e2e_test_project [-h] [-p project_id]'${RESET?}
  echo -e ${RED?}'  -h \t show this help usage'${RESET?}
  echo -e ${RED?}'  -p \t GCP project_id to deploy to'${RESET?}
}

while getopts ':hp:' flag; do
  case "${flag}" in
    h) print_usage
       exit 1 ;;
    p) PROJECT="${OPTARG}" ;;
    *) echo -e ${RED?}'Unknown flag: -'${flag}${RESET?}
       print_usage
       exit 1 ;;
  esac
done

if [[ "${PROJECT}" == "" ]]; then
  echo -e ${RED?}'Must provide a project via $PROJECT or -p project'${RESET?}
  print_usage
  exit 1
fi

echo -e ${GREEN?}'Enabling the required APIs.'${RESET?}

gcloud services enable --project=${PROJECT?} \
  iam.googleapis.com \
  healthcare.googleapis.com \
  cloudbuild.googleapis.com \
  containerregistry.googleapis.com \
  container.googleapis.com \
  compute.googleapis.com

echo -e ${GREEN?}'Create Service Accounts.'${RESET?}

gcloud iam service-accounts create sofuser --project=${PROJECT?} \
    --description="used to run smart on fhir proxy" \
    --display-name="sofuser"

gcloud iam service-accounts create fhiruser --project=${PROJECT?} \
    --description="used to access fhir API" \
    --display-name="fhiruser"

gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:sofuser@${PROJECT?}.iam.gserviceaccount.com --role roles/monitoring.metricWriter
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:sofuser@${PROJECT?}.iam.gserviceaccount.com --role roles/monitoring.viewer
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:sofuser@${PROJECT?}.iam.gserviceaccount.com --role roles/logging.logWriter
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:sofuser@${PROJECT?}.iam.gserviceaccount.com --role roles/storage.objectViewer
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:sofuser@${PROJECT?}.iam.gserviceaccount.com --role roles/iam.serviceAccountTokenCreator

gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:fhiruser@${PROJECT?}.iam.gserviceaccount.com --role roles/healthcare.datasetViewer
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:fhiruser@${PROJECT?}.iam.gserviceaccount.com --role roles/healthcare.datasetAdmin
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:fhiruser@${PROJECT?}.iam.gserviceaccount.com --role roles/healthcare.fhirStoreAdmin
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:fhiruser@${PROJECT?}.iam.gserviceaccount.com --role roles/healthcare.fhirResourceEditor

echo -e ${GREEN?}'Reserve a static external IP address'${RESET?}

gcloud compute addresses create static --global --ip-version=IPV4 --project=${PROJECT?}

echo -e ${GREEN?}'Create GKE cluster'${RESET?}
gcloud container clusters create sof \
  --project=${PROJECT?} \
  --service-account=sofuser@${PROJECT?}.iam.gserviceaccount.com \
  --zone us-central1-a

echo -e ${GREEN?}"Done. You will need to run 'gcloud container clusters get-credentials sof --zone us-central1-a --project=${PROJECT?}' to fetch credentials for kubectl"${RESET?}
