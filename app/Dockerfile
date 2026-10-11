# shop-api demo application image.
#
# One Dockerfile produces all four demo versions. The behaviour is selected by
# the APP_VERSION build argument, which is baked into the image as an ENV var.
# That keeps rollbacks clean: the Deployment only changes the image tag, never
# environment variables.
#
#   docker build -t shop-api:v1 --build-arg APP_VERSION=v1 app/
#   docker build -t shop-api:v2 --build-arg APP_VERSION=v2 app/
#   docker build -t shop-api:v3 --build-arg APP_VERSION=v3 app/
#   docker build -t shop-api:v4 --build-arg APP_VERSION=v4 app/
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

# Non-root user (UID matches runAsUser in k8s/deployment.yaml).
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser

COPY main.py .

# Declared last so the layers above are shared by all four version images.
ARG APP_VERSION=v1
ENV APP_VERSION=${APP_VERSION}

USER 10001
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
