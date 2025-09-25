# Dockerfile
FROM python:3.12.3-slim

# Faster/cleaner Python logs & no .pyc
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Create a non-root user for safety
RUN useradd -m -u 1000 appuser

# System packages: tini for signal handling, curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Leverage layer caching: deps first
COPY requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt

# Copy your app code
COPY . /app

# Ensure the non-root user owns files (esp. for mounted volumes)
RUN chown -R appuser:appuser /app

# Drop privileges
USER appuser

# Streamlit port
EXPOSE 8501

# Entry + CMD
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]
