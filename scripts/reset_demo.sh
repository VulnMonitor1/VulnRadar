#!/usr/bin/env bash
#
# VulnRadar Demo Reset Script
# ===========================
# This script prepares vulnradar-demo for a fresh demo run.
# It syncs the latest code, resets state, and ensures a rich watchlist.
#
# Usage:
#   ./scripts/reset_demo.sh [path_to_vulnradar_demo]
#
# Default: ../vulnradar-demo
#
# What it does:
# 1. Syncs code from VulnRadar (excluding data and state)
# 2. Resets data/state.json so "first run" triggers
# 3. Installs a rich demo watchlist for better presentation
# 4. Commits and optionally pushes changes
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default demo repo path
DEMO_REPO="${1:-../vulnradar-demo}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN_REPO="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}🛡️ VulnRadar Demo Reset Script${NC}"
echo "================================"
echo ""

# Check if demo repo exists
if [ ! -d "$DEMO_REPO" ]; then
    echo -e "${RED}❌ Demo repo not found: $DEMO_REPO${NC}"
    echo ""
    echo "To set up a demo repo:"
    echo "  1. Fork VulnRadar to a new repo (e.g., vulnradar-demo)"
    echo "  2. Clone it: git clone https://github.com/YOU/vulnradar-demo ../vulnradar-demo"
    echo "  3. Run this script again"
    exit 1
fi

# Check if it's a git repo
if [ ! -d "$DEMO_REPO/.git" ]; then
    echo -e "${RED}❌ Not a git repository: $DEMO_REPO${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Found demo repo: $DEMO_REPO${NC}"
echo ""

# Change to demo repo
cd "$DEMO_REPO"

# Step 1: Sync code from main repo
echo -e "${YELLOW}📦 Step 1: Syncing code from main VulnRadar...${NC}"

# Copy Python files and key configs
for file in etl.py notify.py requirements.txt requirements-dev.txt pyproject.toml; do
    if [ -f "$MAIN_REPO/$file" ]; then
        cp "$MAIN_REPO/$file" "./$file"
        echo "  → $file"
    fi
done

# Copy directories
for dir in .github scripts tests docs; do
    if [ -d "$MAIN_REPO/$dir" ]; then
        rm -rf "./$dir"
        cp -r "$MAIN_REPO/$dir" "./$dir"
        echo "  → $dir/"
    fi
done

# Copy devcontainer if exists
if [ -d "$MAIN_REPO/.devcontainer" ]; then
    rm -rf "./.devcontainer"
    cp -r "$MAIN_REPO/.devcontainer" "./.devcontainer"
    echo "  → .devcontainer/"
fi

echo ""

# Step 2: Reset state for first run
echo -e "${YELLOW}🔄 Step 2: Resetting state for first run...${NC}"

mkdir -p data

# Remove state.json to trigger first-run behavior
if [ -f "data/state.json" ]; then
    rm -f "data/state.json"
    echo "  → Removed data/state.json"
else
    echo "  → No state.json to remove"
fi

# Keep radar_data.json if it exists (needed for demo)
if [ -f "data/radar_data.json" ]; then
    echo "  → Keeping existing data/radar_data.json"
else
    echo "  → Note: No radar_data.json - run ETL first for demo data"
fi

echo ""

# Step 3: Install rich demo watchlist
echo -e "${YELLOW}📋 Step 3: Installing rich demo watchlist...${NC}"

cat > watchlist.yaml << 'EOF'
# VulnRadar Demo Watchlist
# ========================
# This watchlist is loaded with popular vendors and products
# for demo purposes. It covers a wide range of common tech stacks.
#
# For your own deployment, customize this to YOUR stack!

# ============================================================================
# VENDORS - Major software organizations
# ============================================================================
vendors:
  # Cloud & Infrastructure
  - microsoft       # Windows, Azure, Office 365, Exchange
  - google          # Chrome, Android, GCP, Workspace
  - amazon          # AWS, various services
  - oracle          # Java, MySQL, Cloud
  
  # Linux & Open Source
  - linux           # Linux kernel
  - apache          # httpd, Tomcat, Struts, Kafka, Log4j
  - canonical       # Ubuntu
  - redhat          # RHEL, OpenShift
  
  # Security & Networking
  - cisco           # IOS, routers, switches
  - fortinet        # FortiGate, FortiOS
  - paloaltonetworks  # PAN-OS, firewalls
  
  # Virtualization & Containers
  - vmware          # ESXi, vCenter, Horizon
  - docker          # Docker Engine
  
  # Browsers & Productivity
  - mozilla         # Firefox, Thunderbird
  - atlassian       # Jira, Confluence
  - gitlab          # GitLab
  
  # Databases
  - postgresql      # PostgreSQL
  - mongodb         # MongoDB

# ============================================================================
# PRODUCTS - Specific high-value software
# ============================================================================
products:
  # Web & App Servers
  - nginx
  - tomcat
  - apache http server
  - iis
  
  # Languages & Runtimes
  - java
  - python
  - node.js
  - php
  
  # Databases
  - mysql
  - postgresql
  - redis
  - elasticsearch
  - mongodb
  
  # Security-Critical Libraries
  - log4j           # Log4Shell and variants
  - openssl         # Heartbleed and others
  - curl            # Common in everything
  - openssh         # Widely deployed
  
  # Productivity & Collaboration
  - exchange        # Microsoft Exchange
  - sharepoint      # Microsoft SharePoint
  - confluence      # Atlassian Confluence
  - jira            # Atlassian Jira
  
  # Infrastructure
  - kubernetes      # K8s
  - jenkins         # CI/CD
  - grafana         # Monitoring
  - prometheus      # Monitoring
  
  # Operating Systems
  - windows         # Microsoft Windows
  - linux kernel    # Linux kernel
  - macos           # Apple macOS
  - android         # Google Android
  - ios             # Apple iOS

# ============================================================================
# EXCLUSIONS - Filter out noise
# ============================================================================
exclude_vendors:
  - n/a
  - unknown
  - unspecified
EOF

echo "  → Created comprehensive demo watchlist"
wc -l watchlist.yaml | awk '{print "  → " $1 " lines in watchlist.yaml"}'

echo ""

# Step 4: Stage changes
echo -e "${YELLOW}📝 Step 4: Staging changes...${NC}"

git add -A
changes=$(git status --porcelain | wc -l | tr -d ' ')

if [ "$changes" -eq "0" ]; then
    echo "  → No changes to commit"
else
    echo "  → $changes files staged"
    git status --short
fi

echo ""

# Step 5: Commit
echo -e "${YELLOW}💾 Step 5: Committing changes...${NC}"

if [ "$changes" -gt "0" ]; then
    git commit -m "chore: sync from main VulnRadar and reset for demo

- Synced latest code from main repo
- Reset state.json for first-run demo
- Updated watchlist with comprehensive demo config"
    echo -e "  ${GREEN}→ Changes committed${NC}"
else
    echo "  → Nothing to commit"
fi

echo ""

# Step 6: Summary
echo -e "${BLUE}════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ Demo repo ready!${NC}"
echo ""
echo "Next steps:"
echo "  1. Push changes:     cd $DEMO_REPO && git push"
echo "  2. Run ETL:          Trigger the ETL workflow in GitHub Actions"
echo "  3. Verify first run: Notify workflow should create baseline issue"
echo ""
echo "For conference demo:"
echo "  - ETL will populate radar_data.json with CVEs matching your watchlist"
echo "  - First notify run creates baseline summary issue"
echo "  - Use --demo flag to inject a fake critical CVE for live demo"
echo ""
echo -e "${BLUE}════════════════════════════════════════════════${NC}"
