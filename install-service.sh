#!/bin/bash
#
# Installation script for IDS systemd service
#
# This script installs the IDS as a systemd service on Linux systems.
# It must be run as root.
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
IDS_USER="root"
IDS_GROUP="root"
IDS_HOME="/opt/ids"
CONFIG_DIR="/etc/ids"
LOG_DIR="/var/log/ids"
SERVICE_NAME="ids"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        echo "Usage: sudo $0"
        exit 1
    fi
}

# Check if systemd is available
check_systemd() {
    if ! command -v systemctl &> /dev/null; then
        print_error "systemctl not found. This script requires systemd."
        exit 1
    fi
}

# Create directories
create_directories() {
    print_status "Creating directories..."
    
    # Create IDS home directory
    mkdir -p "$IDS_HOME"
    chown "$IDS_USER:$IDS_GROUP" "$IDS_HOME"
    
    # Create config directory
    mkdir -p "$CONFIG_DIR"
    chown "$IDS_USER:$IDS_GROUP" "$CONFIG_DIR"
    
    # Create log directory
    mkdir -p "$LOG_DIR"
    chown "$IDS_USER:$IDS_GROUP" "$LOG_DIR"
    
    print_success "Directories created"
}

# Copy IDS files
copy_files() {
    print_status "Copying IDS files..."
    
    # Copy all Python files and directories
    cp -r ids/ "$IDS_HOME/"
    cp ids_main.py "$IDS_HOME/"
    cp main.py "$IDS_HOME/"
    cp ids.py "$IDS_HOME/"
    cp requirements.txt "$IDS_HOME/"
    cp README.md "$IDS_HOME/"
    
    # Copy example config if config doesn't exist
    if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
        cp config.yaml.example "$CONFIG_DIR/config.yaml"
        print_warning "Copied example config to $CONFIG_DIR/config.yaml"
        print_warning "Please edit $CONFIG_DIR/config.yaml with your settings"
    fi
    
    # Set permissions
    chown -R "$IDS_USER:$IDS_GROUP" "$IDS_HOME"
    chmod +x "$IDS_HOME/ids_main.py"
    chmod +x "$IDS_HOME/main.py"
    chmod +x "$IDS_HOME/ids.py"
    
    print_success "Files copied"
}

# Install Python dependencies
install_dependencies() {
    print_status "Installing Python dependencies..."
    
    # Check if pip is available
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 not found. Please install python3-pip"
        exit 1
    fi
    
    # Install dependencies
    pip3 install -r "$IDS_HOME/requirements.txt"
    
    print_success "Dependencies installed"
}

# Install systemd service
install_service() {
    print_status "Installing systemd service..."
    
    # Update service file with correct paths
    sed -e "s|/opt/ids|$IDS_HOME|g" \
        -e "s|/etc/ids|$CONFIG_DIR|g" \
        ids.service > /etc/systemd/system/${SERVICE_NAME}.service
    
    # Reload systemd
    systemctl daemon-reload
    
    print_success "Service installed"
}

# Main installation function
main() {
    echo "=========================================="
    echo "  IDS Systemd Service Installation"
    echo "=========================================="
    echo
    
    check_root
    check_systemd
    
    create_directories
    copy_files
    install_dependencies
    install_service
    
    echo
    print_success "Installation completed!"
    echo
    echo "Next steps:"
    echo "1. Edit configuration: $CONFIG_DIR/config.yaml"
    echo "2. Enable service: systemctl enable $SERVICE_NAME"
    echo "3. Start service: systemctl start $SERVICE_NAME"
    echo "4. Check status: systemctl status $SERVICE_NAME"
    echo "5. View logs: journalctl -u $SERVICE_NAME -f"
    echo
    print_warning "Remember to configure your email settings in $CONFIG_DIR/config.yaml"
}

# Run main function
main "$@"