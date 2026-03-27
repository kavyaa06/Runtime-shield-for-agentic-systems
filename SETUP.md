# Setup Guide for Keycloak MCP Server

This guide provides instructions for setting up the Keycloak MCP server for the first time.

## Prerequisites

- **Node.js**: v20 or higher.
- **Python**: v3.10 or higher.
- **Docker**: Docker Desktop (for Keycloak and SPIRE).

## 1. Professional Installation

Clone the repository and install all dependencies.

### Node.js (MCP Server)
```bash
npm install
```

### Python (Security Bridge)
```bash
# Recommended to use a virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install mcp-firewall-sdk python-dotenv
```

## 2. Infrastructure Setup (Keycloak & SPIRE)

The project uses Docker to manage Keycloak and SPIRE services.

1. Start the containers:
   ```bash
   docker-compose up -d
   ```
2. Verify services are running:
   ```bash
   docker ps
   ```

## 3. Keycloak Configuration

Once Docker is running, you need to configure Keycloak to allow the MCP server to authenticate.

1. Access the Admin Console at [http://localhost:8080](http://localhost:8080).
2. Login with:
   - **Username**: `admin`
   - **Password**: `admin`
3. In the `master` realm (or create a new one):
   - Go to **Clients**.
   - Find or create a client (e.g., `admin-cli`).
   - Go to **Settings** and ensure **Client authentication** is ON.
   - Go to the **Credentials** tab and copy the **Client secret**.

## 4. Environment Setup

Create a `.env` file from the example:

```bash
cp .env.example .env
```

Update your `.env` with the following:
- `KEYCLOAK_CLIENT_SECRET`: Paste the secret you copied from Keycloak.
- `RUNTIME_ROLE`: Set this to `admin`, `analyst`, or `guest` (defaults to `analyst`).

## 5. Building the Project

Compile the TypeScript code:
```bash
npm run build
```

## 6. Running the Secure Bridge

Launch the server with the security bridge active:
```bash
npm run secure-start
```

- **Dashboard**: Access clinical/security events at [http://127.0.0.1:9090](http://127.0.0.1:9090).
- **Scanner**: To run a security scan, use `npm run scan`.

## Troubleshooting

- **Keycloak Connection Refused**: Ensure the docker container is running and healthy.
- **Port 8080 or 8081 in use**: Check if other services are using these ports.
- **SPIRE Failures**: SPIRE is integrated for identity; if it fails to start, verify the `spire/` configuration files.
