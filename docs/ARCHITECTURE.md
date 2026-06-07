# ModTester Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        AWS BEDROCK                               │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  LLM (Claude / GPT / Llama)                              │   │
│  │  Autonomous reasoning + attack planning + tool selection  │   │
│  └──────────────────────────┬───────────────────────────────┘   │
└─────────────────────────────┼───────────────────────────────────┘
                              │
                    MCP (Model Context Protocol)
                              │
┌─────────────────────────────┼───────────────────────────────────┐
│                   MODTESTER SERVER                               │
│                              │                                   │
│  ┌───────────┐  ┌───────────┴──────────┐  ┌──────────────────┐ │
│  │ PLAYBOOKS │  │   TOOL ORCHESTRATION  │  │ VULN DATABASES   │ │
│  │           │  │   (~34 CLI tools)     │  │                  │ │
│  │ • WordPress│  │                      │  │ • MITRE CVE      │ │
│  │ • Jenkins │  │ Recon: subfinder,     │  │ • Exploit-DB     │ │
│  │ • GraphQL │  │   nmap, whois, crtsh  │  │ • GHDB           │ │
│  │ • Spring  │  │ Exploit: metasploit,  │  │ • VulDB          │ │
│  │ • JWT     │  │   sqlmap, commix      │  │ • ENISA EUVD     │ │
│  │ • LFI     │  │ Post-ex: privesc,     │  │ • Nuclei Tmpl    │ │
│  │ • SQLi    │  │   cred dump, pivot    │  │                  │ │
│  │ • Default │  │ Report: generation    │  │                  │ │
│  │   Creds   │  │                       │  │                  │ │
│  └───────────┘  └───────────────────────┘  └──────────────────┘ │
│                                                                  │
│  ┌───────────────────────┐  ┌────────────────────────────────┐  │
│  │ TESTING METHODOLOGIES │  │ COMPLIANCE MAPPING             │  │
│  │                       │  │                                │  │
│  │ • OWASP ASVS 4.0     │  │ • NIST 800-53 Rev 5           │  │
│  │ • OWASP Testing Guide │  │ • PCI-DSS                     │  │
│  │ • PTES                │  │ • CIS Benchmarks              │  │
│  │ • NIST 800-115        │  │ • SOC 2 / HIPAA / GDPR       │  │
│  │ • OWASP MASVS        │  │                                │  │
│  └───────────────────────┘  └────────────────────────────────┘  │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ THREAT MODELING                                             │ │
│  │ STRIDE • DREAD • LINDDUN • PASTA                          │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
                              │
                         VPN Tunnel
                     (AWS Client VPN)
                              │
┌─────────────────────────────┼───────────────────────────────────┐
│              TARGET ENVIRONMENT (Isolated VPC)                    │
│                              │                                   │
│              ┌───────────────┴──────────────────┐               │
│              │  TARGET SYSTEMS                   │               │
│              │  Web apps, APIs, infrastructure   │               │
│              └──────────────────────────────────┘               │
└──────────────────────────────────────────────────────────────────┘
```

## Data Flow

1. **User** types a natural language prompt ("Pentest this target")
2. **Client** sends prompt + conversation history to LLM via Bedrock/Ollama
3. **LLM** reasons about the task and decides which tool to call
4. **Client** forwards tool call to MCP Server via REST
5. **Server** executes the tool (subprocess → CLI binary → target)
6. **Result** flows back: Server → Client → LLM
7. **LLM** analyzes result, decides next action, repeat until complete
8. **Report** generated with findings, evidence, compliance mappings

## Component Details

### Client (`client.py`)
- Interactive CLI with conversation memory
- Supports AWS Bedrock and Ollama-compatible APIs
- Displays argument-aware status messages (never exposes tool names)
- Handles multi-turn tool-calling loops

### Server (`server.py`)
- FastMCP + Starlette application
- Auto-registers tools from `TOOL_REGISTRY`
- Exposes REST API and MCP SSE endpoint
- Stateless: tools execute and return results

### Tools (`tools/`)
- 34 CLI wrapper functions
- Each tool: validate input → build command → subprocess → parse output
- Categories: recon, network, web, vuln, exploit, post-exploit, reporting
- All tools are idempotent (safe to re-run)

### Knowledge (`knowledge/`)
- PTES methodology with 7 phases and exit criteria
- 10 attack playbooks with trigger/action sequences
- OWASP ASVS sample covering the 50 most impactful requirements
- Tool-to-requirement mappings

### Infrastructure (`infra/`)
- CloudFormation: VPC + NAT + Client VPN + ECS Fargate
- Container gets Bedrock access via IAM Task Role
- Operator connects via VPN with zero public exposure
- Split-tunnel VPN (only assessment traffic routed through VPN)

## Security Model

| Layer | Control |
|-------|---------|
| Network | Isolated VPC, no public endpoints |
| Access | Client VPN with mutual TLS |
| Authorization | Rules of Engagement enforced per-tool |
| Identity | IAM Task Role (least privilege) |
| Data | All findings stay in VPC |
| Secrets | Environment variables, never hardcoded |
| Audit | CloudWatch logs for all tool executions |

## Tool Categories

| Category | Tools | Purpose |
|----------|-------|---------|
| DNS/OSINT | dns_lookup, whois, crtsh, subfinder | Passive recon |
| Network | nmap, masscan, netcat | Port/service discovery |
| Web | httpx, ffuf, katana, nikto, waybackurls | Web enumeration |
| Vulnerability | nuclei, sqlmap, commix, testssl | Vuln detection |
| Exploitation | metasploit, searchsploit, msfvenom | Exploitation |
| Verification | verify_sqli/rce/lfi/cve | Confirm findings |
| Post-Exploit | sysinfo, privesc, cred_dump, pivot | Impact assessment |
| Reporting | add_finding, generate_report | Deliverables |
| Threat Model | STRIDE, DREAD, LINDDUN, PASTA | Risk analysis |
