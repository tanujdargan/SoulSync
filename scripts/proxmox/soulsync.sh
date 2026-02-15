#!/usr/bin/env bash

# ============================================================================
#  SoulSync — Proxmox LXC Container Creator
# ============================================================================
#  Creates and configures a Proxmox LXC container, then runs the SoulSync
#  installer inside it.
#
#  Usage (run on the Proxmox VE host):
#    bash -c "$(curl -fsSL https://raw.githubusercontent.com/tanujdargan/SoulSync/main/scripts/proxmox/soulsync.sh)"
#
#  Requirements:
#    - Proxmox VE 7.0+ host
#    - Root privileges on the PVE host
#    - Network connectivity
# ============================================================================

set -Eeuo pipefail

# -- Constants ----------------------------------------------------------------

APP="SoulSync"
INSTALL_SCRIPT_URL="https://raw.githubusercontent.com/tanujdargan/SoulSync/main/scripts/proxmox/soulsync-install.sh"

# Container defaults
DEFAULT_CT_TYPE="1"          # 1 = unprivileged
DEFAULT_CT_PASSWORD="soulsync"
DEFAULT_CT_ID="auto"
DEFAULT_CT_HOSTNAME="soulsync"
DEFAULT_CT_DISK="8"          # GB
DEFAULT_CT_CORES="2"
DEFAULT_CT_RAM="2048"        # MB
DEFAULT_CT_BRIDGE="vmbr0"
DEFAULT_CT_IP="dhcp"
DEFAULT_CT_MTU=""
DEFAULT_CT_DNS=""
DEFAULT_CT_MAC=""
DEFAULT_CT_VLAN=""
DEFAULT_CT_SSH="no"
DEFAULT_CT_VERBOSE="no"
DEFAULT_CT_STORAGE=""

# -- Colors & Formatting (Proxmox community scripts style) --------------------

RD='\033[01;31m'
GN='\033[1;92m'
YW='\033[33m'
YWB='\033[93m'
BL='\033[36m'
BGN='\033[4;92m'
DGN='\033[32m'
CL='\033[m'
BOLD='\033[1m'
DIM='\033[2m'
TAB='  '
BFR="\\r\\033[K"

CM="${TAB}✔️${TAB}${CL}"
CROSS="${TAB}✖️${TAB}${CL}"
INFO="${TAB}💡${TAB}${CL}"
NETWORK="${TAB}📡${TAB}${CL}"
CREATING="${TAB}🚀${TAB}${CL}"
GEAR="${TAB}⚙️${TAB}${CL}"

SPINNER_PID=""

# -- Spinner & Message Functions -----------------------------------------------

spinner() {
  local chars="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
  local i=0
  while true; do
    printf "\r${TAB}${YWB}%s${CL} %s" "${chars:i++%${#chars}:1}" "$1" >&2
    sleep 0.1
  done
}

stop_spinner() {
  if [[ -n "${SPINNER_PID}" ]]; then
    kill "$SPINNER_PID" 2>/dev/null
    wait "$SPINNER_PID" 2>/dev/null || true
    SPINNER_PID=""
  fi
}

msg_info() {
  stop_spinner
  spinner "$1" &
  SPINNER_PID=$!
}

msg_ok() {
  stop_spinner
  printf "${BFR}${CM}${GN}%s${CL}\n" "$1" >&2
}

msg_error() {
  stop_spinner
  printf "${BFR}${CROSS}${RD}%s${CL}\n" "$1" >&2
}

msg_warn() {
  stop_spinner
  printf "${INFO}${YWB}%s${CL}\n" "$1" >&2
}

# -- Cleanup on exit -----------------------------------------------------------

cleanup() {
  stop_spinner
}
trap cleanup EXIT

# -- Error handler -------------------------------------------------------------

error_handler() {
  local exit_code=$?
  local line_number=${1:-unknown}
  stop_spinner
  msg_error "Failed on line ${line_number} (exit code: ${exit_code})"
  exit "$exit_code"
}
trap 'error_handler ${LINENO}' ERR

# -- Header --------------------------------------------------------------------

header_info() {
  clear 2>/dev/null || true
  echo ""
  cat <<"BANNER"
    ____              _  ____
   / ___|  ___  _   _| |/ ___| _   _ _ __   ___
   \___ \ / _ \| | | | |\___ \| | | | '_ \ / __|
    ___) | (_) | |_| | | ___) | |_| | | | | (__
   |____/ \___/ \__,_|_||____/ \__, |_| |_|\___|
                                |___/
BANNER
  echo ""
  echo -e "  ${BL}${BOLD}Proxmox LXC Container Creator${CL}"
  echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${CL}"
  echo ""
}

# -- Prerequisite Checks -------------------------------------------------------

pve_check() {
  if ! command -v pveversion &>/dev/null; then
    msg_error "This script must be run on a Proxmox VE host"
    echo -e "\n${TAB}${DIM}pveversion command not found. Are you on a PVE node?${CL}\n" >&2
    exit 1
  fi
  local pve_ver
  pve_ver=$(pveversion | grep -oP 'pve-manager/\K[0-9]+' || echo "0")
  if [[ "$pve_ver" -lt 7 ]]; then
    msg_error "Proxmox VE 7.0 or later is required (detected: $(pveversion))"
    exit 1
  fi
  msg_ok "Proxmox VE $(pveversion | grep -oP 'pve-manager/\K[^ ]+')"
}

root_check() {
  if [[ "$(id -u)" -ne 0 ]]; then
    msg_error "This script must be run as root"
    echo -e "\n${TAB}Run with: ${GN}sudo bash soulsync.sh${CL}\n" >&2
    exit 1
  fi
}

arch_check() {
  local arch
  arch=$(dpkg --print-architecture 2>/dev/null || uname -m)
  if [[ "$arch" != "amd64" && "$arch" != "x86_64" ]]; then
    msg_error "Unsupported architecture: ${arch}. This script requires amd64/x86_64."
    exit 1
  fi
}

network_check() {
  msg_info "Checking network connectivity"
  local tries=1
  while ! curl -fsSL --max-time 5 https://github.com >/dev/null 2>&1; do
    if [[ $tries -ge 3 ]]; then
      msg_error "No network connectivity (cannot reach github.com)"
      exit 1
    fi
    ((tries++)) || true
    sleep 2
  done
  msg_ok "Network connectivity verified"
}

# -- Prompt Functions ----------------------------------------------------------

prompt_input() {
  local prompt="$1"
  local default="${2:-}"
  local result

  if [[ -n "$default" ]]; then
    printf "\n${TAB}${GEAR} ${YW}%s ${DIM}[%s]${CL}: " "$prompt" "$default" >&2
  else
    printf "\n${TAB}${GEAR} ${YW}%s${CL}: " "$prompt" >&2
  fi
  read -r result </dev/tty
  echo "${result:-$default}"
}

prompt_confirm() {
  local prompt="$1"
  local default="${2:-y}"
  local hint result

  if [[ "$default" == "y" ]]; then
    hint="Y/n"
  else
    hint="y/N"
  fi

  printf "\n${TAB}${INFO} ${YW}%s ${DIM}[%s]${CL}: " "$prompt" "$hint" >&2
  read -r result </dev/tty
  result="${result:-$default}"
  [[ "${result,,}" =~ ^(y|yes)$ ]]
}

prompt_select() {
  local prompt="$1"
  shift
  local options=("$@")

  echo "" >&2
  echo -e "${TAB}${GEAR} ${YW}${prompt}${CL}" >&2
  local i=1
  for opt in "${options[@]}"; do
    echo -e "${TAB}${TAB}${GN}${i})${CL} ${opt}" >&2
    ((i++))
  done

  local result
  while true; do
    printf "${TAB}${TAB}${YW}Select [1-%d]${CL}: " "${#options[@]}" >&2
    read -r result </dev/tty
    if [[ "$result" =~ ^[0-9]+$ ]] && ((result >= 1 && result <= ${#options[@]})); then
      echo "$result"
      return
    fi
    echo -e "${TAB}${TAB}${RD}Invalid selection, try again${CL}" >&2
  done
}

# -- Storage Discovery ---------------------------------------------------------

get_valid_storage() {
  # Find storage pools that support rootdir (container root disks)
  local storage_list
  storage_list=$(pvesm status -content rootdir 2>/dev/null | awk 'NR>1 {print $1}' || true)

  if [[ -z "$storage_list" ]]; then
    msg_error "No storage pools found that support container root disks"
    echo -e "${TAB}${DIM}Ensure you have storage configured for 'rootdir' content type.${CL}" >&2
    exit 1
  fi

  echo "$storage_list"
}

select_storage() {
  local storage_list
  storage_list=$(get_valid_storage)
  local storage_count
  storage_count=$(echo "$storage_list" | wc -l)

  if [[ "$storage_count" -eq 1 ]]; then
    STORAGE=$(echo "$storage_list" | head -1)
    msg_ok "Storage: ${STORAGE} (only available pool)"
    return
  fi

  echo "" >&2
  echo -e "${TAB}${GEAR} ${YW}Select storage pool for the container root disk:${CL}" >&2
  local i=1
  local storages=()
  while IFS= read -r s; do
    local stype sused savail
    stype=$(pvesm status 2>/dev/null | awk -v name="$s" '$1==name {print $2}')
    savail=$(pvesm status 2>/dev/null | awk -v name="$s" '$1==name {printf "%.1fG", $5/1024/1024}')
    echo -e "${TAB}${TAB}${GN}${i})${CL} ${s} ${DIM}(${stype}, ${savail} free)${CL}" >&2
    storages+=("$s")
    ((i++))
  done <<< "$storage_list"

  local result
  while true; do
    printf "${TAB}${TAB}${YW}Select [1-%d]${CL}: " "${#storages[@]}" >&2
    read -r result </dev/tty
    if [[ "$result" =~ ^[0-9]+$ ]] && ((result >= 1 && result <= ${#storages[@]})); then
      STORAGE="${storages[$((result - 1))]}"
      return
    fi
    echo -e "${TAB}${TAB}${RD}Invalid selection, try again${CL}" >&2
  done
}

# -- CT Template ---------------------------------------------------------------

get_template() {
  msg_info "Checking for Debian 12 container template"

  local template_storage
  template_storage=$(pvesm status -content vztmpl 2>/dev/null | awk 'NR>1 {print $1}' | head -1 || true)

  if [[ -z "$template_storage" ]]; then
    msg_error "No storage pool found for container templates (vztmpl)"
    exit 1
  fi

  # Check if a Debian 12 template already exists
  TEMPLATE=$(pveam list "$template_storage" 2>/dev/null \
    | grep -oP '[^ ]+debian-12[^ ]*\.tar\.(gz|zst|xz)' \
    | sort -V | tail -1 || true)

  if [[ -n "$TEMPLATE" ]]; then
    msg_ok "Found template: ${TEMPLATE}"
    return
  fi

  # Download the latest Debian 12 template
  msg_info "Downloading Debian 12 container template"
  pveam update >/dev/null 2>&1 || true

  local available_template
  available_template=$(pveam available -section system 2>/dev/null \
    | grep 'debian-12' \
    | awk '{print $2}' \
    | sort -V | tail -1 || true)

  if [[ -z "$available_template" ]]; then
    msg_error "No Debian 12 template available for download"
    echo -e "${TAB}${DIM}Run 'pveam update' and try again.${CL}" >&2
    exit 1
  fi

  pveam download "$template_storage" "$available_template" >/dev/null 2>&1
  TEMPLATE="${template_storage}:vztmpl/${available_template}"
  msg_ok "Downloaded template: ${available_template}"
}

# -- Next Available CT ID ------------------------------------------------------

next_ct_id() {
  pvesh get /cluster/nextid 2>/dev/null || echo "100"
}

# -- Configuration Phase -------------------------------------------------------

configure_container() {
  echo "" >&2
  echo -e "  ${GEAR}${BOLD}${BL}Container Configuration${CL}" >&2
  echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${CL}" >&2

  if prompt_confirm "Use default settings? (2 cores, 2GB RAM, 8GB disk)" "y"; then
    CT_TYPE="$DEFAULT_CT_TYPE"
    CT_PASSWORD="$DEFAULT_CT_PASSWORD"
    CT_ID=$(next_ct_id)
    CT_HOSTNAME="$DEFAULT_CT_HOSTNAME"
    CT_DISK="$DEFAULT_CT_DISK"
    CT_CORES="$DEFAULT_CT_CORES"
    CT_RAM="$DEFAULT_CT_RAM"
    CT_BRIDGE="$DEFAULT_CT_BRIDGE"
    CT_IP="$DEFAULT_CT_IP"
    CT_MTU=""
    CT_DNS=""
    CT_MAC=""
    CT_VLAN=""
    CT_SSH="$DEFAULT_CT_SSH"
    CT_VERBOSE="$DEFAULT_CT_VERBOSE"

    select_storage

    echo "" >&2
    msg_ok "Using default configuration (CT ID: ${CT_ID})"
    return
  fi

  # -- Advanced configuration --
  echo "" >&2
  echo -e "${TAB}${GEAR} ${YW}Advanced Configuration${CL}" >&2
  echo -e "${TAB}${DIM}Press Enter to accept defaults shown in brackets.${CL}" >&2

  # Container type
  local type_choice
  type_choice=$(prompt_select "Container type:" "Unprivileged (recommended)" "Privileged")
  CT_TYPE=$([[ "$type_choice" == "1" ]] && echo "1" || echo "0")

  # Root password
  CT_PASSWORD=$(prompt_input "Root password for the container" "$DEFAULT_CT_PASSWORD")

  # CT ID
  local auto_id
  auto_id=$(next_ct_id)
  CT_ID=$(prompt_input "Container ID" "$auto_id")

  # Hostname
  CT_HOSTNAME=$(prompt_input "Hostname" "$DEFAULT_CT_HOSTNAME")

  # Storage
  select_storage

  # Disk
  CT_DISK=$(prompt_input "Disk size in GB" "$DEFAULT_CT_DISK")

  # CPU cores
  CT_CORES=$(prompt_input "CPU cores" "$DEFAULT_CT_CORES")

  # RAM
  CT_RAM=$(prompt_input "RAM in MB" "$DEFAULT_CT_RAM")

  # Network
  CT_BRIDGE=$(prompt_input "Network bridge" "$DEFAULT_CT_BRIDGE")

  # IP
  echo "" >&2
  echo -e "${TAB}${DIM}Use 'dhcp' for automatic IP or enter a static IP in CIDR${CL}" >&2
  echo -e "${TAB}${DIM}format (e.g. 192.168.1.100/24).${CL}" >&2
  CT_IP=$(prompt_input "IP address" "$DEFAULT_CT_IP")

  # Gateway (only if static IP)
  CT_GATEWAY=""
  if [[ "$CT_IP" != "dhcp" ]]; then
    echo -e "${TAB}${DIM}Enter the gateway IP without CIDR mask (e.g. 192.168.1.1).${CL}" >&2
    CT_GATEWAY=$(prompt_input "Gateway" "")
    # Strip any accidental CIDR suffix — gateways are plain IPs
    CT_GATEWAY="${CT_GATEWAY%%/*}"
  fi

  # Optional advanced network
  CT_MTU=$(prompt_input "MTU (leave empty for default)" "")
  CT_DNS=$(prompt_input "DNS server (leave empty for host DNS)" "")
  CT_MAC=$(prompt_input "MAC address (leave empty for auto)" "")
  CT_VLAN=$(prompt_input "VLAN tag (leave empty for none)" "")

  # SSH
  if prompt_confirm "Enable root SSH access in the container?" "n"; then
    CT_SSH="yes"
  else
    CT_SSH="no"
  fi

  # Verbose
  if prompt_confirm "Show verbose output during installation?" "n"; then
    CT_VERBOSE="yes"
  else
    CT_VERBOSE="no"
  fi
}

show_config_summary() {
  echo "" >&2
  echo -e "  ${GEAR}${BOLD}Configuration Summary${CL}" >&2
  echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${CL}" >&2
  echo -e "  ${TAB}${DIM}CT Type:${CL}    $([[ "$CT_TYPE" == "1" ]] && echo "Unprivileged" || echo "Privileged")" >&2
  echo -e "  ${TAB}${DIM}CT ID:${CL}      ${CT_ID}" >&2
  echo -e "  ${TAB}${DIM}Hostname:${CL}   ${CT_HOSTNAME}" >&2
  echo -e "  ${TAB}${DIM}Storage:${CL}    ${STORAGE}" >&2
  echo -e "  ${TAB}${DIM}Disk:${CL}       ${CT_DISK}GB" >&2
  echo -e "  ${TAB}${DIM}Cores:${CL}      ${CT_CORES}" >&2
  echo -e "  ${TAB}${DIM}RAM:${CL}        ${CT_RAM}MB" >&2
  echo -e "  ${TAB}${DIM}Bridge:${CL}     ${CT_BRIDGE}" >&2
  echo -e "  ${TAB}${DIM}IP:${CL}         ${CT_IP}" >&2
  [[ -n "${CT_GATEWAY:-}" ]] && echo -e "  ${TAB}${DIM}Gateway:${CL}    ${CT_GATEWAY}" >&2
  [[ -n "${CT_DNS}" ]] && echo -e "  ${TAB}${DIM}DNS:${CL}        ${CT_DNS}" >&2
  [[ -n "${CT_VLAN}" ]] && echo -e "  ${TAB}${DIM}VLAN:${CL}       ${CT_VLAN}" >&2
  echo "" >&2
}

# -- Create Container ----------------------------------------------------------

create_container() {
  msg_info "Creating LXC container (CT ${CT_ID})"

  # Build the network string
  local net_str="name=eth0,bridge=${CT_BRIDGE}"
  if [[ "$CT_IP" == "dhcp" ]]; then
    net_str+=",ip=dhcp"
  else
    net_str+=",ip=${CT_IP}"
    [[ -n "${CT_GATEWAY:-}" ]] && net_str+=",gw=${CT_GATEWAY}"
  fi
  [[ -n "${CT_MTU}" ]] && net_str+=",mtu=${CT_MTU}"
  [[ -n "${CT_MAC}" ]] && net_str+=",hwaddr=${CT_MAC}"
  [[ -n "${CT_VLAN}" ]] && net_str+=",tag=${CT_VLAN}"

  # Build pct create command
  local pct_cmd=(
    pct create "$CT_ID" "$TEMPLATE"
    -hostname "$CT_HOSTNAME"
    -password "$CT_PASSWORD"
    -storage "$STORAGE"
    -rootfs "${STORAGE}:${CT_DISK}"
    -cores "$CT_CORES"
    -memory "$CT_RAM"
    -swap 512
    -net0 "$net_str"
    -unprivileged "$CT_TYPE"
    -features "nesting=1,keyctl=1"
    -onboot 1
    -start 0
  )
  [[ -n "${CT_DNS}" ]] && pct_cmd+=(-nameserver "$CT_DNS")

  local pct_output
  if ! pct_output=$("${pct_cmd[@]}" 2>&1); then
    msg_error "Failed to create container (CT ${CT_ID})"
    echo -e "${TAB}${DIM}pct create output:${CL}" >&2
    echo "$pct_output" >&2
    exit 1
  fi
  msg_ok "Created LXC container (CT ${CT_ID})"
}

# -- Start & Configure Container -----------------------------------------------

start_container() {
  msg_info "Starting container"
  if ! pct start "$CT_ID" 2>&1; then
    msg_error "Failed to start container ${CT_ID}"
    exit 1
  fi

  # Wait for the container to be fully running
  local wait=0
  while [[ "$(pct status "$CT_ID" 2>/dev/null | awk '{print $2}')" != "running" ]]; do
    if [[ $wait -ge 30 ]]; then
      msg_error "Container failed to start within 30 seconds"
      exit 1
    fi
    sleep 1
    ((wait++))
  done
  msg_ok "Container is running"

  # Wait for network inside the container
  msg_info "Waiting for network inside container"
  local net_wait=0
  while ! pct exec "$CT_ID" -- bash -c "ping -c1 -W3 github.com >/dev/null 2>&1 || wget -q --spider --timeout=3 https://github.com 2>/dev/null"; do
    if [[ $net_wait -ge 60 ]]; then
      msg_error "Container has no network connectivity after 60 seconds"
      echo -e "${TAB}${DIM}Check your bridge/VLAN/firewall settings and try again.${CL}" >&2
      exit 1
    fi
    sleep 2
    ((net_wait += 2))
  done
  msg_ok "Container network is ready"
}

configure_ssh() {
  if [[ "$CT_SSH" == "yes" ]]; then
    msg_info "Enabling SSH access"
    pct exec "$CT_ID" -- bash -c "
      apt-get update -qq >/dev/null 2>&1
      apt-get install -y -qq openssh-server >/dev/null 2>&1
      sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
      systemctl enable ssh >/dev/null 2>&1
      systemctl restart ssh >/dev/null 2>&1
    " >/dev/null 2>&1
    msg_ok "SSH access enabled"
  fi
}

# -- Run Installer Inside Container --------------------------------------------

run_installer() {
  echo "" >&2
  echo -e "  ${CREATING}${BOLD}${GN}Running SoulSync installer inside CT ${CT_ID}${CL}" >&2
  echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${CL}" >&2
  echo "" >&2

  # Ensure curl is available, then download and run the installer
  pct exec "$CT_ID" -- bash -c "
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq curl >/dev/null 2>&1
    curl -fsSL '${INSTALL_SCRIPT_URL}' -o /tmp/soulsync-install.sh
    chmod +x /tmp/soulsync-install.sh
    bash /tmp/soulsync-install.sh
    rm -f /tmp/soulsync-install.sh
  "
}

# -- Completion Banner ---------------------------------------------------------

show_completion() {
  local ct_ip
  ct_ip=$(pct exec "$CT_ID" -- bash -c "hostname -I 2>/dev/null | awk '{print \$1}'" 2>/dev/null || echo "<container-ip>")

  echo "" >&2
  echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${CL}" >&2
  echo -e "  ${CREATING}${GN}${BOLD}LXC container created and SoulSync installed!${CL}" >&2
  echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${CL}" >&2
  echo "" >&2

  echo -e "  ${NETWORK}${YW}SoulSync Web UI${CL}     ${BGN}http://${ct_ip}:8008${CL}" >&2
  echo -e "  ${NETWORK}${YW}slskd Web UI${CL}        ${BGN}http://${ct_ip}:5030${CL}" >&2

  echo "" >&2
  echo -e "  ${GEAR}${BOLD}Container Details${CL}" >&2
  echo -e "  ${TAB}${DIM}CT ID:${CL}       ${CT_ID}" >&2
  echo -e "  ${TAB}${DIM}Hostname:${CL}    ${CT_HOSTNAME}" >&2
  echo -e "  ${TAB}${DIM}IP:${CL}          ${ct_ip}" >&2
  [[ "$CT_SSH" == "yes" ]] && echo -e "  ${TAB}${DIM}SSH:${CL}         ssh root@${ct_ip}" >&2

  echo "" >&2
  echo -e "  ${GEAR}${BOLD}Proxmox Commands${CL}" >&2
  echo -e "  ${TAB}${DIM}Console:${CL}     pct enter ${CT_ID}" >&2
  echo -e "  ${TAB}${DIM}Start:${CL}       pct start ${CT_ID}" >&2
  echo -e "  ${TAB}${DIM}Stop:${CL}        pct stop ${CT_ID}" >&2
  echo -e "  ${TAB}${DIM}Destroy:${CL}     pct destroy ${CT_ID}" >&2

  echo "" >&2
  echo -e "  ${GEAR}${BOLD}Inside Container${CL}" >&2
  echo -e "  ${TAB}${DIM}SoulSync:${CL}    systemctl {start|stop|restart|status} soulsync" >&2
  echo -e "  ${TAB}${DIM}slskd:${CL}       systemctl {start|stop|restart|status} slskd" >&2
  echo -e "  ${TAB}${DIM}Config:${CL}      /opt/soulsync/config/config.json" >&2
  echo -e "  ${TAB}${DIM}Logs:${CL}        /opt/soulsync/logs/" >&2

  echo "" >&2
  echo -e "  ${INFO}${YW}Next steps:${CL}" >&2
  echo -e "  ${TAB}1. Open the SoulSync web UI at ${BGN}http://${ct_ip}:8008${CL}" >&2
  echo -e "  ${TAB}2. Complete Spotify OAuth by clicking 'Connect' in Settings" >&2
  echo -e "  ${TAB}3. Start syncing your music library!" >&2
  echo "" >&2
}

# -- Main Execution ------------------------------------------------------------

main() {
  header_info
  root_check
  arch_check
  pve_check
  network_check

  get_template
  configure_container
  show_config_summary

  if ! prompt_confirm "Create this container and install SoulSync?"; then
    echo -e "\n${TAB}${DIM}Cancelled.${CL}\n" >&2
    exit 0
  fi

  echo "" >&2

  create_container
  start_container
  configure_ssh
  run_installer
  show_completion
}

main "$@"
