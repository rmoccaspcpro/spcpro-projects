# Multi-stage build optimized for ARM64 (Raspberry Pi)
FROM python:3.11-slim-bookworm AS builder

WORKDIR /build

# Install dependencies
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim-bookworm

WORKDIR /app

# Copy dependencies from builder
COPY --from=builder /root/.local /root/.local

# Copy application code
COPY app/ ./app/
COPY requirements.txt .

# Create data directory for SQLite
RUN mkdir -p /app/data

# Add Python user packages to PATH
ENV PATH=/root/.local/bin:$PATH

# Expose port
EXPOSE 8000

# Run uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
