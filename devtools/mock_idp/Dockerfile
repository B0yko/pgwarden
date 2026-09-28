# Development-only mock OIDC identity provider.
# Not part of the pgwarden wheel or the production gateway image.
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

RUN groupadd --system --gid 10001 mockidp \
    && useradd --system --uid 10001 --gid mockidp --no-create-home --shell /usr/sbin/nologin mockidp

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir --no-compile -r requirements.txt

COPY app.py users.yaml ./
COPY templates/ ./templates/

RUN chown -R mockidp:mockidp /app
USER mockidp

EXPOSE 9400

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9400/healthz', timeout=2).status == 200 else 1)"

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9400"]
