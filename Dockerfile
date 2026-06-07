# =============================================================================
# MCP Offensive Security Demo — Container Image
#
# Build:    docker build -t mcp-offsec-demo .
# Run:      docker run -d -p 8000:8000 --env-file .env mcp-offsec-demo
#
# Based on Kali Linux with ~34 pre-installed offensive security tools.
# First build: ~15 min (cached). Code changes: <30 sec rebuild.
# =============================================================================

#######################
# STAGE 1: Fetch pre-built binaries
#######################
FROM python:3.12-slim-bookworm AS fetcher

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget unzip git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /tools && cd /tools \
    && curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip -o nuclei.zip \
    && curl -sL https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip -o katana.zip \
    && curl -sL https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip -o httpx.zip \
    && curl -sL https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip -o subfinder.zip \
    && curl -sL https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz -o ffuf.tar.gz \
    && curl -sL https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-linux-amd64-0.1.0.tgz -o waybackurls.tgz \
    && curl -sL https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz -o gobuster.tar.gz \
    && curl -sL https://github.com/epi052/feroxbuster/releases/download/v2.11.0/x86_64-linux-feroxbuster.tar.gz -o feroxbuster.tar.gz \
    && curl -sL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz -o chisel.gz \
    && unzip -o nuclei.zip -d . 2>/dev/null; unzip -o katana.zip -d . 2>/dev/null \
    && unzip -o httpx.zip -d . 2>/dev/null; unzip -o subfinder.zip -d . 2>/dev/null \
    && tar -xzf ffuf.tar.gz 2>/dev/null; tar -xzf waybackurls.tgz 2>/dev/null \
    && tar -xzf gobuster.tar.gz 2>/dev/null; tar -xzf feroxbuster.tar.gz 2>/dev/null \
    && gunzip chisel.gz 2>/dev/null || true \
    && rm -rf *.zip *.tar.gz *.tgz \
    && chmod +x nuclei katana httpx subfinder ffuf waybackurls feroxbuster gobuster chisel 2>/dev/null || true

RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
    && git clone --depth 1 https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng \
    && git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && rm -rf /opt/testssl.sh/.git /opt/enum4linux-ng/.git /opt/nikto/.git

# Wordlists
RUN mkdir -p /opt/wordlists/dirb /opt/wordlists/passwords \
    && curl -sL -o /opt/wordlists/dirb/common.txt \
       https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt \
    && curl -sL -o /opt/wordlists/dirb/big.txt \
       https://raw.githubusercontent.com/v0re/dirb/master/wordlists/big.txt \
    && curl -sL -o /opt/wordlists/subdomains.txt \
       https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt \
    && curl -sL -o /opt/wordlists/passwords/default-creds.txt \
       https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/default-credentials.csv


#######################
# STAGE 2: Final image
#######################
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv python3-dev \
    nmap masscan netcat-openbsd whois dnsutils sslscan \
    hydra smbclient sshpass \
    metasploit-framework exploitdb \
    curl wget git ca-certificates unzip jq \
    build-essential libffi-dev libssl-dev \
    perl libnet-ssleay-perl \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Pre-built binaries
COPY --from=fetcher /tools/nuclei /tools/katana /tools/httpx /tools/subfinder \
    /tools/ffuf /tools/waybackurls /tools/feroxbuster /tools/gobuster \
    /tools/chisel /usr/local/bin/

COPY --from=fetcher /opt/testssl.sh /opt/testssl.sh
COPY --from=fetcher /opt/enum4linux-ng /opt/enum4linux-ng
COPY --from=fetcher /opt/nikto /opt/nikto
COPY --from=fetcher /opt/wordlists /usr/share/wordlists

# Symlinks
RUN ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
    && ln -sf /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

# Metasploit DB init
RUN msfdb init 2>/dev/null || true

# Python security tools
RUN pip install --no-cache-dir --break-system-packages \
    sqlmap commix arjun \
    theHarvester shodan \
    pexpect python-whois dnspython requests

# Working dirs
RUN mkdir -p /tmp/reports /tmp/scans /app/reports /app/sessions

# ===========================================================
# APP LAYER
# ===========================================================
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

COPY config.py .
COPY server.py .
COPY client.py .
COPY db.py .
COPY chat_api.py .
COPY auth.py .
COPY audit.py .
COPY roe.py .
COPY tools/ ./tools/
COPY knowledge/ ./knowledge/

RUN mkdir -p /app/reports /app/sessions /app/evidence

EXPOSE 8000

ENV MCP_PORT=8000
ENV AI_BACKEND=bedrock
ENV SHOW_TOOL_NAMES=false

CMD ["python3", "server.py"]
