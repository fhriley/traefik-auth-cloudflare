FROM golang:1.14.2

WORKDIR /go/src/github.com/fhriley/traefik-auth-cloudflare
COPY . .
# Static build required so that we can safely copy the binary over.
RUN go install github.com/fhriley/traefik-auth-cloudflare

ENTRYPOINT ["traefik-auth-cloudflare"]
