#!/bin/bash

set -e

IMAGE="quay.io/cloudservices/mbop"  # the image location on quay

# We will run rbac smoke tests to validate mbop is working

APP_NAME="rbac"  # name of app-sre "application" folder this component lives in
COMPONENT_NAME="rbac"  # name of app-sre "resourceTemplate" in deploy.yaml for this component
IQE_PLUGINS="rbac,rbac_frontend"  # name of the IQE plugin for this APP
IQE_MARKER_EXPRESSION="outage"  # This is the value passed to pytest -m
IQE_CJI_TIMEOUT="10m"  # This is the time to wait for smoke test to complete or fail
DEPLOY_FRONTENDS=true
IQE_SELENIUM=true
IQE_ENV=ephemeral

# Install bonfire repo/initialize
CICD_URL=https://raw.githubusercontent.com/RedHatInsights/bonfire/master/cicd
curl -s $CICD_URL/bootstrap.sh > .cicd_bootstrap.sh && source .cicd_bootstrap.sh

source $CICD_ROOT/unit_test.sh
source $CICD_ROOT/build.sh
source $CICD_ROOT/deploy_ephemeral_env.sh

# Update mbop in this environment to use the newly built PR image
CLOWDENV_NAME="env-$NAMESPACE"
kubectl patch clowdenvironment ${CLOWDENV_NAME} --type='merge' -p '{"spec":{"providers":{"web":{"images":{"mockBop":"'${IMAGE}:${IMAGE_TAG}'"}}}}}'
kubectl rollout status deployment/${CLOWDENV_NAME}-mbop

source $CICD_ROOT/cji_smoke_test.sh
