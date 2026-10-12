FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install only the package and its runtime dependencies; tests, Git metadata,
# local AWS profiles and generated reports are excluded by .dockerignore.
COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir . \
    && useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin scanner \
    && mkdir -p /app/reports \
    && chown -R scanner:scanner /app

USER 10001:10001

ENTRYPOINT ["aws-security-scan"]
