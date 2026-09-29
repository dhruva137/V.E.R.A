# One image serving both halves: the API and the dashboard it renders.
#
# Two stages so node is only needed to build the front end and never ships in
# the runtime image.

# --- Stage 1: build the dashboard -----------------------------------------
FROM node:20-alpine AS frontend

WORKDIR /build
# Copy manifests first so the dependency layer caches across source edits.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# --- Stage 2: runtime ------------------------------------------------------
FROM python:3.12-slim

# Keeps the image small and makes tracebacks appear in logs immediately.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./

# The built dashboard, served by FastAPI at / so there is no second service
# and no cross-origin configuration.
COPY --from=frontend /build/dist ./static
ENV VERA_STATIC_DIR=/app/static

# Writable by default; mount a volume here to keep scan history across deploys.
ENV VERA_DB_PATH=/app/data/vera.db
RUN mkdir -p /app/data

EXPOSE 8000

# Shell form so ${PORT} expands - Railway, Fly and Render all inject it.
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
