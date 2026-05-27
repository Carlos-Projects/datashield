FROM python:3.11-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install hatch && hatch build

FROM python:3.11-slim

WORKDIR /app
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install /tmp/datashield_ai-*.whl && rm /tmp/datashield_ai-*.whl

ENTRYPOINT ["datashield"]
CMD ["--help"]
