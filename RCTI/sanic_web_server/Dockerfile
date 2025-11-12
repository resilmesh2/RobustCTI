# Sanic Web Server Backend Dockerfile
FROM python:3.9

# python:3.9 already has gcc/g++ and curl, skip apt install

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY pyproject.toml ./

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -e .

# Copy application source
COPY src/ ./src/
COPY tests/ ./tests/

# Add src/server to PYTHONPATH so 'from correlate import' works
ENV PYTHONPATH="/app/src/server:${PYTHONPATH}"

# Create directories for data
RUN mkdir -p ./docs/attackflow_graphs && \
    mkdir -p ./alerts && \
    mkdir -p ./config

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash app && \
    chown -R app:app /app
USER app

# Set environment variables for paths
ENV PROJECT_ROOT=/app \
    BUILDER_PATH=/app/attack_flow_builder/dist \
    STIX_VIZ_PATH=/app/cti-stix-visualization \
    FLOW_DIR=/app/docs/attackflow_graphs \
    STORAGE_PATH=/app/alerts \
    STIX_STORAGE_PATH=/app/docs

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["python", "-m", "src.server.server"]