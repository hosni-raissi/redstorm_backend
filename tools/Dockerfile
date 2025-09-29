# Multi-stage build for Go security tools
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o redstorm-tools .

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    ca-certificates \
    curl \
    wget \
    bind-tools \
    whois \
    fping \
    hping3 \
    python3 \
    python3-dev \
    py3-pip \
    ruby \
    ruby-dev \
    build-base \
    git

# Install Amass
RUN wget -O amass.zip https://github.com/OWASP/Amass/releases/latest/download/amass_linux_amd64.zip && \
    unzip amass.zip && \
    mv amass_linux_amd64/amass /usr/local/bin/ && \
    rm -rf amass.zip amass_linux_amd64

# Install Nuclei
RUN wget -O nuclei.tar.gz https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.1.0_linux_amd64.tar.gz && \
    tar -xzf nuclei.tar.gz && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei.tar.gz

# Install Subfinder
RUN wget -O subfinder.tar.gz https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_2.6.3_linux_amd64.tar.gz && \
    tar -xzf subfinder.tar.gz && \
    mv subfinder /usr/local/bin/ && \
    rm subfinder.tar.gz

# Install Gobuster
RUN wget -O gobuster.tar.gz https://github.com/OJ/gobuster/releases/latest/download/gobuster_Linux_x86_64.tar.gz && \
    tar -xzf gobuster.tar.gz && \
    mv gobuster /usr/local/bin/ && \
    rm gobuster.tar.gz

RUN git clone https://github.com/rapid7/metasploit-framework.git /opt/metasploit-framework && \
    cd /opt/metasploit-framework && \
    gem install bundler && \
    bundle install --without development test && \
    ln -s /opt/metasploit-framework/msfconsole /usr/local/bin/msfconsole

RUN git clone https://github.com/EmpireProject/Empire.git /opt/empire && \
    cd /opt/empire && \
    pip3 install -r requirements.txt && \
    ln -s /opt/empire/empire /usr/local/bin/empire

RUN git clone https://github.com/dradis/dradis-ce.git /opt/dradis && \
    cd /opt/dradis && \
    gem install bundler && \
    bundle install --without development test && \
    ln -s /opt/dradis/bin/dradis /usr/local/bin/dradis

# Create wordlists directory
RUN mkdir -p /usr/share/wordlists/dirb && \
    wget -O /usr/share/wordlists/dirb/common.txt https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt

# Copy built binary
COPY --from=builder /app/redstorm-tools /usr/local/bin/

# Create non-root user
RUN adduser -D -s /bin/sh redstorm
USER redstorm

ENTRYPOINT ["/usr/local/bin/redstorm-tools"]
