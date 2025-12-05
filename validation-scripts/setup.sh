#!/bin/bash
#
# Setup script for Conntrack Race Condition Reproducer
# This script validates prerequisites and helps set up the test environment
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=================================================="
echo "Conntrack Race Condition Reproducer - Setup"
echo "=================================================="
echo ""

# Check kubectl
echo -n "Checking kubectl... "
if command -v kubectl &> /dev/null; then
    KUBECTL_VERSION=$(kubectl version --client --short 2>/dev/null || kubectl version --client 2>&1 | grep "Client Version" | cut -d: -f2)
    echo -e "${GREEN}✓${NC} Found: $KUBECTL_VERSION"
else
    echo -e "${RED}✗${NC} kubectl not found"
    echo "Please install kubectl: https://kubernetes.io/docs/tasks/tools/"
    exit 1
fi

# Check kubectl cluster access
echo -n "Checking cluster access... "
if kubectl cluster-info &> /dev/null; then
    echo -e "${GREEN}✓${NC} Connected to cluster"
    CLUSTER_NAME=$(kubectl config current-context 2>/dev/null || echo "unknown")
    echo "  Current context: $CLUSTER_NAME"
else
    echo -e "${RED}✗${NC} Cannot connect to cluster"
    echo "Please configure kubectl with cluster credentials"
    exit 1
fi

# Check Python
echo -n "Checking Python... "
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo -e "${GREEN}✓${NC} Found: $PYTHON_VERSION"
else
    echo -e "${RED}✗${NC} python3 not found"
    echo "Please install Python 3.8 or later"
    exit 1
fi

# Check/Install PyYAML
echo -n "Checking PyYAML... "
if python3 -c "import yaml" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Installed"
else
    echo -e "${YELLOW}!${NC} Not found, installing..."
    pip3 install pyyaml
    if python3 -c "import yaml" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Successfully installed PyYAML"
    else
        echo -e "${RED}✗${NC} Failed to install PyYAML"
        echo "Please install manually: pip3 install pyyaml"
        exit 1
    fi
fi

# Check permissions
echo ""
echo "Checking Kubernetes permissions..."

echo -n "  Can create namespace... "
if kubectl auth can-i create namespace &> /dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${YELLOW}!${NC} May need additional permissions"
fi

echo -n "  Can create pods... "
if kubectl auth can-i create pods -n conntrack-test &> /dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${YELLOW}!${NC} May need additional permissions"
fi

echo -n "  Can exec into pods... "
if kubectl auth can-i create pods/exec -n conntrack-test &> /dev/null; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${YELLOW}!${NC} May need additional permissions"
fi

# Make script executable
echo ""
echo "Making Python script executable..."
chmod +x conntrack_race_reproducer.py
echo -e "${GREEN}✓${NC} Done"

echo ""
echo "=================================================="
echo "Setup complete!"
echo "=================================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Deploy test resources:"
echo "   kubectl apply -f k8s_test_pods.yaml"
echo ""
echo "2. Wait for pods to be ready:"
echo "   kubectl wait --for=condition=ready pod/test-client -n conntrack-test --timeout=60s"
echo "   kubectl wait --for=condition=ready pod/test-server -n conntrack-test --timeout=60s"
echo ""
echo "3. (Optional) Edit test_config.yaml to match your environment"
echo ""
echo "4. Run the reproducer:"
echo "   python3 conntrack_race_reproducer.py"
echo ""
echo "For more information, see README.md"
echo ""
