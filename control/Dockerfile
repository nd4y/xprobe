# The service is light: FastAPI + httpx + sqlite. No registry in this setup —
# the image is built on the host, so the stack must be deployed with
# pullImage: false.
FROM python:3.13-slim

WORKDIR /app
RUN pip install --no-cache-dir "fastapi>=0.115" "uvicorn>=0.30" "httpx>=0.27"

COPY control /app/control
# Two apps on two ports: 8080 — points (public), 8081 — admin (internal).
EXPOSE 8080 8081

RUN useradd --system --create-home xpc
USER xpc

CMD ["python", "-m", "control"]
