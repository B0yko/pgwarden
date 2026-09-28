# pgwarden gateway image. Multi-stage: dependencies are installed from uv.lock
# with hashes, the wheel is built from src/ only, and the runtime runs as a
# non-root user. devtools/ (mock IdP, screenshot script) is never copied in.
FROM ghcr.io/astral-sh/uv:0.12.9@sha256:8b940d3a9d65bed080436972241af2e21c84b5e8c9193f7014ed71479ee795ff AS uv

FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS build
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
COPY src ./src
RUN uv export --frozen --no-dev --no-emit-project --format requirements-txt -o /requirements.txt \
    && uv build --wheel --out-dir /dist

FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
LABEL org.opencontainers.image.title="pgwarden" \
      org.opencontainers.image.description="Governed Postgres access for AI assistants (MCP gateway)" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/B0yko/pgwarden"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY --from=build /requirements.txt /tmp/requirements.txt
COPY --from=build /dist/ /tmp/dist/
RUN pip install --require-hashes -r /tmp/requirements.txt \
    && pip install --no-deps /tmp/dist/*.whl \
    && rm -rf /tmp/requirements.txt /tmp/dist \
    && groupadd --system --gid 10001 pgwarden \
    && useradd --system --uid 10001 --gid pgwarden --no-create-home --shell /usr/sbin/nologin pgwarden
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"
ENTRYPOINT ["pgwarden"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
