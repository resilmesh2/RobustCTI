# Attack Flow System - Docker Deployment

This document describes how to deploy the integrated Attack Flow system using Docker and Docker Compose.

## Architecture

The system consists of three main components:

1. **Attack Flow Builder** (`attackflow_builder`) - Vue.js frontend for creating attack flows
   - Port: 8080
   - Access: http://localhost:8080

2. **Sanic Web Server** (`sanic_web_server`) - Python backend for processing alerts
   - Port: 8000
   - Access: http://localhost:8000
   - API endpoints for flow management and STIX pattern validation

3. **STIX Modeler** (`stix_modeler`) - React UI for STIX object visualization
   - Port: 3000
   - Access: http://localhost:3000

4. **CTI STIX Visualization** - OASIS CTI STIX visualization library (served by Sanic backend)
   - Access: http://localhost:8000/cti-stix-visualization

## Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- At least 4GB RAM available for Docker

## Quick Start

1. Clone the repository and navigate to the project root:
   ```bash
   cd /path/to/attackflow
   ```

2. Copy the environment file:
   ```bash
   cp .env.example .env
   ```

3. Build and start all services:
   ```bash
   docker-compose up --build
   ```

4. Access the applications:
   - Attack Flow Builder: http://localhost:8080
   - Sanic Web Server API: http://localhost:8000
   - Attack Flow Builder (via backend): http://localhost:8000/builder
   - CTI STIX Visualization: http://localhost:8000/cti-stix-visualization
   - STIX Modeler: http://localhost:3000

## Individual Service Management

### Build specific service:
```bash
# Build only the frontend
docker-compose build attackflow_builder

# Build only the backend
docker-compose build sanic_web_server

# Build only the STIX modeler
docker-compose build stix_modeler
```

### Start specific service:
```bash
# Start only the backend
docker-compose up sanic_web_server

# Start frontend and backend
docker-compose up attackflow_builder sanic_web_server
```

## Development Mode

For development, you can run services individually:

```bash
# Start backend only
docker-compose up sanic_web_server

# Start frontend in development (outside Docker)
cd attack_flow_builder
npm run serve
```

## API Endpoints

The Sanic Web Server provides these endpoints:

### Core Endpoints
- `GET /` - Server home page
- `GET /health` - Health check with flow status
- `GET /routes` - List all available routes

### Flow Management
- `GET /flow` - Get current flow status and metadata
- `POST /flow/reset` - Reset the global attack flow
- `GET /api/flows` - List available attack flow files
- `GET /api/flows/<flow_name>` - Get specific flow file contents
- `POST /api/flows/upload` - Upload new flow file (.json or .afb)
- `POST /api/flows/activate/<flow_name>` - Activate a new attack flow

### STIX Pattern Validation
- `POST /api/validate-pattern` - Validate single STIX pattern
- `POST /api/validate-flow` - Validate all patterns in a flow

### Alert Processing
- `POST /wazuh-alerts` - Process security alerts and correlate with attack flow

### Atomic Red Team Integration
- `POST /api/upload-schedule` - Upload attack schedule file to Kali
- `POST /api/run-atomic` - Execute Atomic Red Team tests via Kali

### Static Content
- `/builder` - Attack Flow Builder frontend (Vue.js)
- `/cti-stix-visualization` - STIX visualization tool

## Data Persistence

- Alert storage: `backend_alerts` volume
- STIX bundles: `backend_stix` volume
- Attack flow files: `./docs` directory (mounted read-only)

## Troubleshooting

### Port Conflicts
If ports are in use, modify the `.env` file:
```bash
ATTACKFLOW_BUILDER_PORT=8080
SANIC_WEB_SERVER_PORT=8001
STIX_MODELER_PORT=3001
```

### Build Issues
Clear Docker cache:
```bash
docker-compose down
docker system prune -a
docker-compose build --no-cache
```

### View Logs
```bash
# All services
docker-compose logs

# Specific service
docker-compose logs sanic_web_server
docker-compose logs attackflow_builder
docker-compose logs stix_modeler
```

## Stopping Services

```bash
# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```