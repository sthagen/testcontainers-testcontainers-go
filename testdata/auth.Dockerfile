ARG REGISTRY_PORT=5001

FROM localhost:${REGISTRY_PORT}/redis:5.0-alpine
