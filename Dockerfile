FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml ./
COPY src ./src
RUN python -m pip install --no-cache-dir "build>=1.2,<2" "hatchling>=1.25,<2"
RUN python -m build --wheel --no-isolation --outdir /tmp/dist

FROM python:3.12-slim AS runtime

WORKDIR /app
COPY --from=builder /tmp/dist /tmp/dist
RUN python -m pip install --no-cache-dir /tmp/dist/*.whl
ENV PYQUALITY_MODE=public_mock
EXPOSE 8000
CMD ["pyquality", "serve", "--host", "0.0.0.0", "--port", "8000", "--public-mock"]
