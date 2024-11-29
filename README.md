# rust_auth0_service



## Cloudflare

```deploy.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: cloudflare
  name: cloudflared
  labels:
    app: cloudflared
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cloudflared
  template:
    metadata:
      labels:
        app: cloudflared
    spec:
      containers:
      - name: cloudflared
        image: cloudflare/cloudflared:latest
        command: ["cloudflared", "tunnel", "--no-autoupdate", "run"]
        env:
        - name: TUNNEL_TOKEN
          valueFrom:
            secretKeyRef:
              name: cloudflared-token
              key: token
```

```ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
  namespace: auth0
spec:
  ingressClassName: cloudflared
  rules:
  - host: app.<Domain>
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: login-test
            port:
              number: 3005
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name:  rust-auth0-ingress
  namespace: auth0 
spec:
  ingressClassName: cloudflared
  rules:
  - host: auth.<Domain>
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: rust-auth0-service
            port:
              number: 8080
```
