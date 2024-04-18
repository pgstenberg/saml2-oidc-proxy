# syntax=docker/dockerfile:1

################################################
# Build
################################################
FROM golang:1.21.4

WORKDIR /build
COPY . ./

# Download Go modules
RUN go mod download
# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o ./saml2-oidc-proxy cmd/main.go

################################################
# Application
################################################
FROM scratch
COPY --from=0 /build/saml2-oidc-proxy /bin/saml2-oidc-proxy

# Expose Port
EXPOSE 8080
ENTRYPOINT ["/bin/saml2-oidc-proxy"]