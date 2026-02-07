# ----------------------------
# Build the frontend
FROM node:lts-alpine as frontend-build

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ .
RUN npm run build

# ----------------------------
# Build the backend
FROM golang:1.22-alpine as backend-build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o webcve

# ----------------------------
# Final image
FROM alpine:latest

WORKDIR /app

# Copy the Go binary
COPY --from=backend-build /app/webcve .

# Copy the Vue frontend dist
COPY --from=frontend-build /app/frontend/dist ./frontend/dist

# Create directories for data that will be mounted
RUN mkdir -p /app/cves /app/kev

# Expose port
EXPOSE 3000

CMD ["/app/webcve"]
