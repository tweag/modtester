# ModTester Setup Guide

## Prerequisites

- **Docker** (20.10+) and Docker Compose
- **AWS CLI** configured with Bedrock access (or Ollama running locally)
- **Python 3.10+** (for running client locally)

## Quick Start (Local)

```bash
# 1. Clone and enter
git clone https://github.com/ModusCreate-NFR/mcp-security-tool.git -b mcp-offsec-demo modtester
cd modtester

# 2. Configure
cp .env.example .env
# Edit .env with your AI_BACKEND and credentials

# 3. Build and run
docker compose up -d

# 4. Connect client
pip install -r requirements.txt
python client.py
```

## Quick Start (AWS ECS)

```bash
# 1. Configure AWS CLI
aws configure

# 2. Deploy infrastructure
cd infra
chmod +x deploy.sh
./deploy.sh modtester us-east-1

# 3. Connect via VPN and run client
python client.py
```

## AI Backend Options

### AWS Bedrock (Recommended for demo)

1. Ensure your AWS account has Bedrock model access enabled
2. Request access to Claude models in the AWS Console → Bedrock → Model Access
3. Set in `.env`:
   ```
   AI_BACKEND=bedrock
   AWS_REGION=us-east-1
   BEDROCK_MODEL=us.anthropic.claude-sonnet-4-20250514-v1:0
   ```

### Ollama (Local/Self-hosted)

1. Install Ollama: https://ollama.ai
2. Pull a model: `ollama pull llama3.1:70b`
3. Set in `.env`:
   ```
   AI_BACKEND=ollama
   OLLAMA_URL=http://localhost:11434
   OLLAMA_MODEL=llama3.1:70b
   ```

## Verifying the Setup

```bash
# Check server health
curl http://localhost:8000/health
# Expected: {"status": "healthy", "tools_available": 34}

# Check tools loaded
curl http://localhost:8000/tools | python -m json.tool | head -20

# Test client connection
python client.py "What tools do you have?"
```

## Network Requirements

The container needs outbound internet access to:
- Reach targets being assessed
- Download nuclei templates (first run)
- Query external APIs (crt.sh, Wayback Machine)

Targets must be reachable from the container's network.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Cannot connect to server" | Ensure `docker compose up -d` is running |
| "Bedrock access denied" | Request model access in AWS Console |
| "No tools loaded" | Check container logs: `docker compose logs api` |
| "Scan timed out" | Target may be unreachable from container network |
| Tool returns empty results | Tool binary may be missing, rebuild image |
