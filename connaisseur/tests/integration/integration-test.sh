#! /bin/bash
set -euo pipefail

# This script is expected to be called from the root folder of Connaisseur

if [[ -z "${RELEASE_IMAGE-}" ]] || [[ -z "${RELEASE_VERSION-}" ]]; then
  echo "Missing environment variables."
  exit 1
fi

echo 'Preparing Connaisseur config...'
envsubst < connaisseur/tests/integration/update-config.yaml > update
yq write --inplace --script update helm/values.yaml # Coincidentally, this also ensure all used env variables are set
rm update
echo 'Config set'

echo 'Installing Connaisseur...'
make install || { echo 'Failed to install Connaisseur'; exit 1; }
echo 'Successfully installed Connaisseur'

echo 'Testing unsigned image...'
kubectl run pod --image=connytest/testimage:unsigned >output.log 2>&1 || true

if [[ "$(cat output.log)" != 'Error from server: admission webhook "connaisseur-svc.connaisseur.svc" denied the request: could not find signed digest for image "docker.io/connytest/testimage:unsigned" in trust data.' ]]; then
  echo 'Failed to deny unsigned image or failed with unexpected error. Output:'
  cat output.log
  exit 1
else
  echo 'Successfully denied usage of unsigned image'
fi

echo 'Testing image signed under different key...'
kubectl run pod --image=securesystemsengineering/connaisseur:signed >output.log 2>&1 || true

if [[ "$(cat output.log)" != 'Error from server: admission webhook "connaisseur-svc.connaisseur.svc" denied the request: failed to verify signature of trust data.' ]]; then
  echo 'Failed to deny image signed different key or failed with unexpected error. Output:'
  cat output.log
  exit 1
else
  echo 'Successfully denied usage of image signed under different key'
fi

echo 'Testing signed image...'
kubectl run pod --image=connytest/testimage:signed >output.log 2>&1 || true

if [[ "$(cat output.log)" != 'pod/pod created' ]]; then
  echo 'Failed to allow signed image. Output:'
  cat output.log
  exit 1
else
  echo 'Successfully allowed usage of signed image'
fi

echo 'Testing deployment of unsigned init container along with a valid container...'
kubectl apply -f connaisseur/tests/integration/valid_container_with_unsigned_init_container_image.yml >output.log 2>&1 || true

if [[ "$(cat output.log)" != 'Error from server: error when creating "connaisseur/tests/integration/valid_container_with_unsigned_init_container_image.yml": admission webhook "connaisseur-svc.connaisseur.svc" denied the request: could not find signed digest for image "docker.io/connytest/testimage:unsigned" in trust data.' ]]; then
  echo 'Allowed an unsigned image via init container or failed due to an unexpected error handling init containers. Output:'
  cat output.log
  exit 1
else
  echo 'Successfully denied unsigned image in init container'
fi

echo 'Uninstalling Connaisseur...'
make uninstall || { echo 'Failed to uninstall Connaisseur'; exit 1; }
echo 'Successfully uninstalled Connaisseur'

rm output.log
echo 'Passed integration test'
