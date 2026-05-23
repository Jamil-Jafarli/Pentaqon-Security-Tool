#!/bin/bash
export GROQ_API_KEY="${GROQ_API_KEY:-$1}"

if [ -z "$GROQ_API_KEY" ]; then
  echo "Usage: ./start.sh <your-groq-api-key>"
  echo "   or: GROQ_API_KEY=<key> ./start.sh"
  exit 1
fi

echo "Starting SOC AI Assistant on http://0.0.0.0:5000"
cd "$(dirname "$0")"
./venv/bin/python app.py
