# Build stage for frontend and rule compilation
FROM node:20-slim as frontend-builder

WORKDIR /app/frontend
COPY frontend/package.json frontend/yarn.lock ./
RUN yarn install --frozen-lockfile --production

COPY frontend/ ./
RUN yarn build

# Rule compilation stage
FROM python:3.12-slim as rule-builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy rule fetching and compilation scripts
COPY scripts/fetch_rules_v2.sh scripts/compile_rules_v2.py scripts/
RUN chmod +x scripts/*.sh scripts/*.py

# Install Python dependencies for rule compilation
COPY backend/requirements.txt backend/
RUN pip install --no-cache-dir -r backend/requirements.txt

# Create rule directories and fetch/compile rules
RUN mkdir -p rules/{sigma,yara,compiled,local} \
    && scripts/fetch_rules_v2.sh \
    && python3 scripts/compile_rules_v2.py

# Production stage - minimal runtime image
FROM python:3.12-slim

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libmagic1 \
    libmagic-mgc \
    curl \
    supervisor \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create application directory
WORKDIR /app

# Copy Python requirements and install runtime dependencies
COPY backend/requirements.txt backend/
RUN pip install --no-cache-dir -r backend/requirements.txt \
    && pip cache purge

# Copy backend application
COPY backend/ backend/

# Copy compiled frontend from builder stage
COPY --from=frontend-builder /app/frontend/build frontend/build

# Copy compiled rules from rule-builder stage
COPY --from=rule-builder /app/rules/compiled rules/compiled
COPY --from=rule-builder /app/rules/sources.json rules/sources.json

# Copy runtime scripts (excluding build-time scripts)
COPY scripts/refresh_worker.py scripts/weekly_refresh.sh scripts/
RUN chmod +x scripts/*.py scripts/*.sh

# Create local rules directory for user uploads
RUN mkdir -p rules/local \
    && mkdir -p /tmp/edrscan \
    && chmod 700 /tmp/edrscan

# Copy environment templates
COPY backend/.env.template backend/.env
COPY frontend/.env.template frontend/.env

# Copy supervisor configuration
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Create log directories
RUN mkdir -p /var/log/supervisor

# Expose ports
EXPOSE 3000 8001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8001/api/rules/stats || exit 1

# Start supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]