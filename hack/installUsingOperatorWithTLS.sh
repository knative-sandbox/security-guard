#!/usr/bin/env bash

# Copyright 2022 The Knative Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

echo "Copy the certificate to file"
ROOTCA="$(mktemp)"
FILENAME=`basename $ROOTCA`
kubectl get secret -n knative-serving knative-serving-certs -o json| jq -r '.data."ca-cert.pem"' | base64 -d >  $ROOTCA

echo "Create a temporary config-deployment configmap with the certificate"
CERT=`kubectl create cm config-deployment --from-file $ROOTCA -o json --dry-run=client |jq .data.\"$FILENAME\"`

echo "cleanup"
rm $ROOTCA

echo "Apply new Knative Operator configuration"
kubectl apply --filename - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: knative-serving
---
apiVersion: operator.knative.dev/v1beta1
kind: KnativeServing
metadata:
  name: knative-serving
  namespace: knative-serving
spec:
  deployments:
  - name: guard-service
    env:
    - container: guard-service
      envVars:
      - name: GUARD_SERVICE_TLS
        value: "true"
      - name: GUARD_SERVICE_AUTH
        value: "true"
  security:
    securityGuard:
      enabled: true
  ingress:
    kourier:
      enabled: true
  config:
    network:
      ingress.class: "kourier.ingress.networking.knative.dev"
    deployment:
      queue-sidecar-rootca: ${CERT}
      queue-sidecar-token-audiences: guard-service
EOF

kubectl get KnativeServing -n knative-serving -o yaml
