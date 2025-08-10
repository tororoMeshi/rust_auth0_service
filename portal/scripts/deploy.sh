#!/bin/bash

set -e

echo "🚀 Portal Kubernetes Deployment Script"

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl is not installed or not in PATH"
    exit 1
fi

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed or not in PATH"
    exit 1
fi

# Build and push frontend image
echo "📦 Building frontend image..."
cd "$(dirname "$0")/.."
docker build -t tororomeshi/portal-frontend:latest .
docker push tororomeshi/portal-frontend:latest

# Build and push backend image
echo "📦 Building backend image..."
cd ../portal-backend
docker build -t tororomeshi/portal-backend:latest .
docker push tororomeshi/portal-backend:latest

# Deploy to Kubernetes
echo "🚀 Deploying to Kubernetes namespace: auth0..."
cd ../portal/k8s

# Apply all manifests to auth0 namespace
kubectl apply -f frontend-configmap.yaml -n auth0
kubectl apply -f frontend-deployment.yaml -n auth0
kubectl apply -f frontend-service.yaml -n auth0
kubectl apply -f ../portal-backend/k8s/backend-configmap.yaml -n auth0
kubectl apply -f ../portal-backend/k8s/backend-deployment.yaml -n auth0
kubectl apply -f ../portal-backend/k8s/backend-service.yaml -n auth0
kubectl apply -f ../portal-backend/k8s/backend-networkpolicy.yaml -n auth0
kubectl apply -f ingress.yaml -n auth0

# Wait for deployments to be ready
echo "⏳ Waiting for deployments to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/frontend-deployment -n auth0
kubectl wait --for=condition=available --timeout=300s deployment/backend-deployment -n auth0

echo "✅ Deployment completed successfully!"
echo "📊 Check deployment status:"
echo "   kubectl get pods -n auth0"
echo "   kubectl get services -n auth0"
echo "   kubectl get ingress -n auth0"