# syntax=docker/dockerfile:1.7
# Self-cloning build for the fabriclab host (see deploy/README.md).
# The GitHub deploy key is passed with `docker build --ssh default=<key>` and is
# only visible inside RUN --mount=type=ssh, so it never lands in an image layer
# or the build cache.

FROM alpine:3 AS source
ARG GIT_REF=main
RUN apk add --no-cache git openssh-client \
    && mkdir -p -m 0700 /root/.ssh \
    && ssh-keyscan github.com >> /root/.ssh/known_hosts 2>/dev/null
RUN --mount=type=ssh \
    git init -q /src && cd /src \
    && git fetch -q --depth 1 git@github.com:ftntcsecanada/webcve.git "$GIT_REF" \
    && git checkout -q FETCH_HEAD \
    && git rev-parse HEAD > /src/.commit \
    && rm -rf .git

FROM node:22-alpine AS frontend
WORKDIR /app/frontend
COPY --from=source /src/frontend/package.json /src/frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY --from=source /src/frontend/ ./
# vite builds into ../site
RUN npm run build

FROM golang:1.27-alpine AS backend
WORKDIR /app
COPY --from=source /src/go.mod /src/go.sum ./
RUN go mod download
COPY --from=source /src/*.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o webcve

FROM alpine:3
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=backend /app/webcve ./
COPY --from=frontend /app/site ./site
COPY --from=source /src/.commit ./.commit
RUN mkdir -p cves kev
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD wget -qO- http://127.0.0.1:3000/api/health >/dev/null || exit 1
CMD ["/app/webcve"]
