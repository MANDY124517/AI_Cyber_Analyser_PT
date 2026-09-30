# ==============================================================================
# CyberTriage Enterprise AI - Self-Contained Production Dockerfile
# Bundles Python 3.11 + FastAPI + Ollama & LLM Model (hermes3:3b)
# ==============================================================================

FROM python:3.11-slim

# Install system dependencies & curl for Ollama installation
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install Ollama binary
RUN curl -fsSL https://ollama.com/install.sh | sh

# Pre-download and bake the LLM model (hermes3:3b) directly into the image layer
RUN ollama serve > /dev/null 2>&1 & \
    PID=$! && \
    while ! curl -s http://127.0.0.1:11434/api/tags > /dev/null 2>&1; do sleep 1; done && \
    ollama pull hermes3:3b && \
    kill $PID

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application codebase
COPY . .

# Set execution permissions on startup script
RUN chmod +x entrypoint.sh

# Configure environment defaults for standalone production deployment
ENV PYTHONUNBUFFERED=1 \
    PORT=8000 \
    HOST=0.0.0.0 \
    LLM_PROVIDER=ollama \
    USE_OLLAMA=true \
    OLLAMA_HOST=http://127.0.0.1:11434 \
    OLLAMA_MODEL=hermes3:3b \
    ALLOW_MOCK_FALLBACK=false

# Expose Web/API and Ollama ports
EXPOSE 8000 11434

# Run self-contained entrypoint
ENTRYPOINT ["./entrypoint.sh"]
