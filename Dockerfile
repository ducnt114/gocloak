FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /gocloak ./cmd/gocloak && mkdir /data
# Keycloak's admin console (Apache License 2.0), from Maven Central.
# Build with --build-arg ADMIN_CONSOLE=false to leave it out.
ARG ADMIN_CONSOLE=true
RUN mkdir -p /admin-console && if [ "$ADMIN_CONSOLE" = "true" ]; then /gocloak download-admin-console --dir /admin-console; fi

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /gocloak /gocloak
COPY --from=build /admin-console /opt/gocloak/admin-console
COPY --from=build --chown=65532:65532 /data /data
ENV GOCLOAK_DB=/data/gocloak.db GOCLOAK_ADMIN_CONSOLE_DIR=/opt/gocloak/admin-console
VOLUME /data
EXPOSE 8080 8443
ENTRYPOINT ["/gocloak"]
CMD ["start-dev"]
