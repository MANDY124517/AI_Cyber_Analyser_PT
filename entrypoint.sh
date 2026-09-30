#!/bin/bash
set -e

echo "=========================================================="
echo " Starting CyberTriage Enterprise AI & Ollama Runtime..."
echo "=========================================================="

mkdir -p /app/logs

# 1. Start Ollama in the background if enabled
if [ "${USE_OLLAMA}" = "true" ] || [ "${LLM_PROVIDER}" = "ollama" ]; then
    echo "[*] Starting Ollama server..."
    ollama serve > /app/logs/ollama.log 2>&1 &
    OLLAMA_PID=$!

    echo "[*] Waiting for Ollama engine to initialize..."
    for i in $(seq 1 30); do
        if curl -s http://127.0.0.1:11434/api/tags > /dev/null 2>&1; then
            echo "[+] Ollama server is UP and responsive."
            break
        fi
        sleep 1
    done

    MODEL_NAME="${OLLAMA_MODEL:-hermes3:3b}"
    echo "[*] Verifying model availability: ${MODEL_NAME}..."
    if ! ollama list | grep -q "${MODEL_NAME}"; then
        echo "[*] Model '${MODEL_NAME}' not found in image cache. Pulling now..."
        ollama pull "${MODEL_NAME}"
        echo "[+] Model '${MODEL_NAME}' pulled successfully."
    else
        echo "[+] Model '${MODEL_NAME}' verified in local cache."
    fi
fi

# 2. Start FastAPI Server
PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"
echo "[*] Starting CyberTriage Web & API server on http://${HOST}:${PORT}..."
exec uvicorn api.server:app --host "${HOST}" --port "${PORT}"
