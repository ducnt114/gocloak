FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /gocloak ./cmd/gocloak && mkdir /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /gocloak /gocloak
COPY --from=build --chown=65532:65532 /data /data
ENV GOCLOAK_DB=/data/gocloak.db
VOLUME /data
EXPOSE 8080 8443
ENTRYPOINT ["/gocloak"]
CMD ["start-dev"]
