#!/bin/bash

# Copyright 2019 Google LLC
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
  echo -e ${RED?}'Usage: prepare_project [-h] [-p project_id]'${RESET?}
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

PROJECT_NUMBER=$(gcloud projects list --filter="${PROJECT?}" --format="value(PROJECT_NUMBER)")
if [[ "$?" != 0 ]]; then
  exit 1
fi

echo -e ${GREEN?}'Preparing the GCP project '${PROJECT?}' for deployment.'${RESET?}
# Enbable the required APIs.
echo -e ${GREEN?}'Enabling the required APIs.'${RESET?}

gcloud services enable --project=${PROJECT?}\
  appengine.googleapis.com \
  appengineflex.googleapis.com \
  appenginestandard.googleapis.com \
  cloudbuild.googleapis.com

# Create a GAE app.
gcloud app create --project=${PROJECT?} --region=us-central

# Deploy a simple defaut app to GAE default service.
echo -e ${GREEN?}'Deploy a helloworld to GAE default service.'${RESET?}

tempdir=`mktemp -d`
pushd $tempdir
git clone https://github.com/GoogleCloudPlatform/golang-samples.git
pushd golang-samples/appengine/go11x/helloworld
gcloud app deploy --project=${PROJECT?} --version=master -q .
popd
popd
rm -rf $tempdir

echo -e ${GREEN?}'Project preparation complete.'${RESET?}
