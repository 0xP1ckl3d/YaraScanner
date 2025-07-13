FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    wget \
    unzip \
    libmagic1 \
    libmagic-mgc \
    curl \
    cron \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js for frontend
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs

# Create application directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY backend/requirements.txt /app/backend/
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy application code
COPY . /app/

# Setup frontend dependencies
WORKDIR /app/frontend
RUN npm install && npm run build

# Setup rule directories
WORKDIR /app
RUN mkdir -p /app/rules/{sigma,yara,compiled,local} \
    && mkdir -p /tmp/edrscan \
    && chmod 700 /tmp/edrscan

# Copy environment templates
RUN cp backend/.env.template backend/.env \
    && cp frontend/.env.template frontend/.env

# Make scripts executable
RUN chmod +x /app/scripts/*.sh /app/scripts/*.py

# Fetch and compile rules at build time
RUN /app/scripts/fetch_rules_v2.sh \
    && python3 /app/scripts/compile_rules_v2.py

# Setup supervisor
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Setup weekly cron job
RUN echo "0 3 * * 1 root /app/scripts/weekly_refresh.sh >> /var/log/rule_refresh.log 2>&1" >> /etc/crontab

# Expose ports
EXPOSE 3000 8001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8001/api/rules/stats || exit 1

# Start supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]