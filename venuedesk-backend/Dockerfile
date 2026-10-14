FROM python:3.11-slim

# System build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Dedicated unprivileged service user
RUN useradd -m -u 1000 -s /bin/bash venuedesk

WORKDIR /app

# Install backend dependencies and Gunicorn
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir gunicorn psycopg2-binary && \
    pip install --no-cache-dir -e .

# Copy application source tree
COPY . .

# Adjust permissions
RUN chown -R venuedesk:venuedesk /app
USER venuedesk

ENV FLASK_ENV=production \
    PORT=5001 \
    PYTHONUNBUFFERED=1

EXPOSE 5001

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:5001/healthz || exit 1

CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:create_app()"]
