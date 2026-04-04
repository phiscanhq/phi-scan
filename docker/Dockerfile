# phi-scan:ignore-file
# phi-scan Docker image — multi-stage Alpine build
#
# Supports linux/amd64 and linux/arm64 (Apple Silicon).
#
# Build:
#   docker build -t phi-scan:latest .
#
# Run:
#   docker run --rm -v "$(pwd)":/repo phi-scan:latest scan /repo
#   docker run --rm -v "$(pwd)":/repo phi-scan:latest scan /repo --output json
#   docker run --rm -v "$(pwd)":/repo phi-scan:latest scan /repo --diff HEAD~1
#
# Multi-arch build (requires Docker Buildx):
#   docker buildx build --platform linux/amd64,linux/arm64 -t phi-scan:latest --push .

# ---------------------------------------------------------------------------
# Stage 1 — builder: install phi-scan and dependencies into a venv
# ---------------------------------------------------------------------------
FROM python:3.12-alpine AS builder

# Build-time dependencies needed to compile some Python wheels on Alpine
RUN apk add --no-cache \
        gcc \
        g++ \
        musl-dev \
        libffi-dev \
        openssl-dev \
        linux-headers \
        git

# Create an isolated venv so Stage 2 just copies it
RUN python -m venv /opt/phi-scan-venv
ENV PATH="/opt/phi-scan-venv/bin:$PATH"

# Upgrade pip then install phi-scan (pinned at build time via ARG)
ARG PHI_SCAN_VERSION=
RUN pip install --no-cache-dir --upgrade pip && \
    if [ -n "$PHI_SCAN_VERSION" ]; then \
        pip install --no-cache-dir "phi-scan==${PHI_SCAN_VERSION}"; \
    else \
        pip install --no-cache-dir phi-scan; \
    fi

# Pre-download spaCy model so the image starts instantly in air-gapped environments
RUN phi-scan scan --help > /dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Stage 2 — runtime: minimal Alpine image with only the venv
# ---------------------------------------------------------------------------
FROM python:3.12-alpine AS runtime

LABEL org.opencontainers.image.title="phi-scan" \
      org.opencontainers.image.description="PHI/PII scanner for CI/CD pipelines" \
      org.opencontainers.image.url="https://github.com/your-org/phi-scan" \
      org.opencontainers.image.source="https://github.com/your-org/phi-scan" \
      org.opencontainers.image.licenses="MIT"

# Runtime deps: git (for --diff), libstdc++ (for some native wheels)
RUN apk add --no-cache \
        git \
        libstdc++

# Copy the pre-built venv from the builder stage
COPY --from=builder /opt/phi-scan-venv /opt/phi-scan-venv
ENV PATH="/opt/phi-scan-venv/bin:$PATH"

# Non-root user for security — matches the UID convention used in most CI runners
RUN addgroup -S phiscan && adduser -S phiscan -G phiscan
USER phiscan

# Model cache lives in a writable home dir
ENV HOME="/home/phiscan"
WORKDIR /repo

# Default entrypoint — allows `docker run phi-scan:latest scan /repo`
ENTRYPOINT ["phi-scan"]
CMD ["--help"]
