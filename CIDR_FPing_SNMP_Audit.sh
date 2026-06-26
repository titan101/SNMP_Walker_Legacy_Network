#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# CIDR_FPing_SNMP_Audit.sh
# Made by Varun and Copilot.
#
# One-pass Ubuntu/Linux audit:
#   1. Accept CIDR blocks from a file, arguments, or pasted stdin.
#   2. Use fping to find alive IPs per CIDR block.
#   3. SNMP poll each alive IP with community strings from a local file.
#   4. Write sorted CSV inventory output with the source CIDR on every row.
#   5. Write executive summary CSVs by subnet and by subnet + device model.
###############################################################################

SCRIPT_VERSION="2026.06.25"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
STAMP="$(date +"%Y%m%d_%H%M%S")"

CIDR_FILE=""
COMMUNITY_FILE="${SCRIPT_DIR}/community_strings.txt"
OUTPUT_DIR="${SCRIPT_DIR}/Audit_Results_${STAMP}"
MAX_SNMP_JOBS=50
FPING_RETRIES=1
FPING_TIMEOUT_MS=700
SNMP_RETRIES=1
SNMP_TIMEOUT_SEC=1
NO_SNMP=0

declare -a CIDRS=()
declare -a COMMUNITIES=()
declare -A SEEN_CIDR=()

RUN_LOG=""
ERROR_LOG=""
TMP_DIR=""
DETAIL_CSV=""
ALIVE_CSV=""
SUBNET_SUMMARY_CSV=""
MODEL_SUMMARY_CSV=""
ALIVE_PAIRS_FILE=""

usage() {
  cat <<'EOF'
Usage:
  ./CIDR_FPing_SNMP_Audit.sh -i cidrs.txt
  ./CIDR_FPing_SNMP_Audit.sh 10.10.10.0/24 10.10.20.0/24
  printf '%s\n' 10.10.10.0/24 10.10.20.0/24 | ./CIDR_FPing_SNMP_Audit.sh

Options:
  -i, --cidr-file FILE       File with one CIDR block per line.
  -c, --community-file FILE  SNMP community file. Default: community_strings.txt beside this script.
  -o, --output-dir DIR       Output directory. Default: Audit_Results_YYYYMMDD_HHMMSS beside this script.
      --snmp-jobs N          Parallel SNMP jobs. Default: 50.
      --fping-retries N      fping retries. Default: 1.
      --fping-timeout MS     fping timeout in milliseconds. Default: 700.
      --snmp-retries N       SNMP retries. Default: 1.
      --snmp-timeout SEC     SNMP timeout in seconds. Default: 1.
      --no-snmp              Only run fping and write alive IP CSV.
  -h, --help                 Show this help.

Ubuntu dependencies:
  sudo apt-get update
  sudo apt-get install -y fping snmp

Notes:
  - Community strings are never printed to the screen or written to CSV.
  - If the community file is missing or empty, the script prompts for a path
    or lets you create one before the scan starts.
  - Detailed CSV rows include the source CIDR block so Excel can filter by subnet.
  - The summary CSV rolls devices up by source CIDR, normalized vendor/family, and model.
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  local message="$*"
  local line
  line="[$(date +"%H:%M:%S")] ${message}"
  printf '%s\n' "$line"
  if [[ -n "${RUN_LOG:-}" ]]; then
    printf '%s\n' "$line" >> "$RUN_LOG"
  fi
}

section() {
  log "----------------------------------------------------------------"
  log "$*"
  log "----------------------------------------------------------------"
}

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

is_ipv4() {
  local ip="${1:-}"
  local a b c d octet

  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r a b c d <<< "$ip"
  for octet in "$a" "$b" "$c" "$d"; do
    [[ "$octet" =~ ^[0-9]+$ ]] || return 1
    (( 10#$octet >= 0 && 10#$octet <= 255 )) || return 1
  done
}

is_cidr() {
  local cidr="${1:-}"
  local ip prefix

  [[ "$cidr" == */* ]] || return 1
  ip="${cidr%/*}"
  prefix="${cidr#*/}"
  is_ipv4 "$ip" || return 1
  [[ "$prefix" =~ ^[0-9]+$ ]] || return 1
  (( 10#$prefix >= 0 && 10#$prefix <= 32 )) || return 1
}

cidr_usable_ips() {
  local cidr="$1"
  local prefix="${cidr#*/}"
  local host_bits
  local total

  prefix=$((10#$prefix))
  host_bits=$((32 - prefix))

  if (( prefix == 32 )); then
    total=1
  elif (( prefix == 31 )); then
    total=2
  else
    total=$(((1 << host_bits) - 2))
  fi

  printf '%s' "$total"
}

add_cidr() {
  local cidr
  cidr="$(trim "${1:-}")"

  [[ -z "$cidr" ]] && return 0
  [[ "${cidr:0:1}" == "#" ]] && return 0
  is_cidr "$cidr" || die "Invalid CIDR '${cidr}'. Expected format like 10.10.10.0/24."

  if [[ -z "${SEEN_CIDR[$cidr]:-}" ]]; then
    CIDRS+=("$cidr")
    SEEN_CIDR[$cidr]=1
  fi
}

expand_user_path() {
  local path="${1:-}"

  if [[ "$path" == "~" ]]; then
    path="${HOME}"
  elif [[ "$path" == "~/"* ]]; then
    path="${HOME}/${path#"~/"}"
  fi

  printf '%s' "$path"
}

community_file_has_values() {
  local file="${1:-}"
  local line

  [[ -f "$file" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="$(trim "$line")"
    [[ -z "$line" ]] && continue
    [[ "${line:0:1}" == "#" ]] && continue
    return 0
  done < "$file"

  return 1
}

create_community_file_interactively() {
  local target_file="$1"
  local target_dir
  local temp_file
  local community
  local count=0

  target_file="$(expand_user_path "$target_file")"
  target_dir="$(dirname -- "$target_file")"
  mkdir -p "$target_dir"
  temp_file="$(mktemp "${target_dir}/.community_strings.XXXXXX")"
  chmod 600 "$temp_file"

  {
    printf '# SNMP community strings - one per line\n'
    printf '# Made by Varun and Copilot. Created on %s\n' "$(date)"
  } > "$temp_file"

  printf '\nEnter SNMP community strings one at a time.\n' > /dev/tty
  printf 'Input is hidden. Press Enter on a blank line when done.\n\n' > /dev/tty

  while true; do
    printf 'Community %d: ' "$((count + 1))" > /dev/tty
    IFS= read -r -s community < /dev/tty || true
    printf '\n' > /dev/tty
    community="$(trim "$community")"

    [[ -z "$community" ]] && break
    printf '%s\n' "$community" >> "$temp_file"
    (( count += 1 ))
  done

  if (( count == 0 )); then
    rm -f "$temp_file"
    printf 'No community strings entered. Nothing was saved.\n' > /dev/tty
    return 1
  fi

  mv "$temp_file" "$target_file"
  chmod 600 "$target_file"
  COMMUNITY_FILE="$target_file"
  printf 'Saved %d community string(s) to %s\n' "$count" "$COMMUNITY_FILE" > /dev/tty
}

ensure_community_file_ready() {
  local choice
  local entered_path
  local create_path

  (( NO_SNMP == 1 )) && return 0
  community_file_has_values "$COMMUNITY_FILE" && return 0

  printf 'Community file missing or empty: %s\n' "$COMMUNITY_FILE" >&2
  if [[ ! -r /dev/tty || ! -w /dev/tty ]]; then
    die "Cannot prompt because this session has no interactive terminal. Create the file, pass -c /path/to/community_strings.txt, or rerun with --no-snmp."
  fi

  while true; do
    {
      printf '\nSNMP community setup is required before the scan can start.\n'
      printf 'Community strings will not be printed or written to CSV.\n'
      printf '  1) Enter path to an existing community file\n'
      printf '  2) Create a community file now\n'
      printf '  3) Continue with fping only (--no-snmp)\n'
      printf '  4) Exit\n'
      printf 'Choose 1-4: '
    } > /dev/tty

    IFS= read -r choice < /dev/tty || die "Could not read community setup choice."
    choice="$(trim "$choice")"

    case "$choice" in
      1)
        printf 'Path to existing community file: ' > /dev/tty
        IFS= read -r entered_path < /dev/tty || true
        entered_path="$(expand_user_path "$(trim "$entered_path")")"
        if community_file_has_values "$entered_path"; then
          COMMUNITY_FILE="$entered_path"
          printf 'Using community file: %s\n' "$COMMUNITY_FILE" > /dev/tty
          return 0
        fi
        printf 'That file was not found or has no usable community strings.\n' > /dev/tty
        ;;
      2)
        printf 'Save community file path [%s]: ' "$COMMUNITY_FILE" > /dev/tty
        IFS= read -r create_path < /dev/tty || true
        create_path="$(trim "$create_path")"
        [[ -z "$create_path" ]] && create_path="$COMMUNITY_FILE"
        if create_community_file_interactively "$create_path"; then
          return 0
        fi
        ;;
      3)
        NO_SNMP=1
        printf 'Continuing with fping only. SNMP polling and model summaries will show skipped/no SNMP data.\n' > /dev/tty
        return 0
        ;;
      4|q|Q|quit|exit)
        die "Community setup cancelled."
        ;;
      *)
        printf 'Please choose 1, 2, 3, or 4.\n' > /dev/tty
        ;;
    esac
  done
}

csv_escape() {
  local value="${1:-}"

  value="${value//$'\r'/ }"
  value="${value//$'\n'/ }"
  value="${value//$'\t'/ }"
  value="${value//\"/\"\"}"

  if [[ "$value" == *","* || "$value" == *'"'* ]]; then
    printf '"%s"' "$value"
  else
    printf '%s' "$value"
  fi
}

csv_row() {
  local first=1
  local field

  for field in "$@"; do
    if (( first == 0 )); then
      printf ','
    fi
    csv_escape "$field"
    first=0
  done
  printf '\n'
}

clean_snmp_value() {
  local value="${1:-NA}"

  value="${value//$'\r'/ }"
  value="${value//$'\n'/ }"
  value="$(printf '%s' "$value" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/^"//; s/"$//')"
  [[ -z "$value" ]] && value="NA"
  printf '%s' "$value"
}

normalize_word() {
  local value="${1:-Unknown}"
  value="$(trim "$value")"
  [[ -z "$value" ]] && value="Unknown"
  printf '%s' "$value"
}

classify_device() {
  local sys_object_id="${1:-}"
  local sys_descr="${2:-}"
  local text lower family model token

  text="${sys_descr} ${sys_object_id}"
  lower="$(printf '%s' "$text" | tr '[:upper:]' '[:lower:]')"
  family="Unknown"
  model="Unknown"

  if [[ "$lower" =~ (juniper|junos|jnpr) ]]; then
    family="Juniper"
    if [[ "$lower" =~ (ex[0-9]{4}(-[a-z0-9+]+)?) ]]; then
      model="${BASH_REMATCH[1]^^}"
    elif [[ "$lower" =~ (acx[0-9]{4}) ]]; then
      model="${BASH_REMATCH[1]^^}"
    elif [[ "$lower" =~ (mx[0-9]+) ]]; then
      model="${BASH_REMATCH[1]^^}"
    elif [[ "$lower" =~ (qfx[0-9]{4}(-[a-z0-9]+)?) ]]; then
      model="${BASH_REMATCH[1]^^}"
    else
      model="Juniper Unknown"
    fi

  elif [[ "$lower" =~ (ciena|saos|service[[:space:]]delivery|service[[:space:]]aggregation|fsp150|fsp[[:space:]]150|optiswitch|t-marc|t5c-xg|waveserver|cn[[:space:]-]*[0-9]{4}) ]]; then
    family="Ciena"
    if [[ "$lower" =~ cn[[:space:]-]*([0-9]{4}) ]]; then
      model="CN ${BASH_REMATCH[1]}"
    elif [[ "$lower" =~ (^|[^0-9])([35][0-9]{3})([^0-9]|$) ]]; then
      model="${BASH_REMATCH[2]}"
    elif [[ "$lower" =~ fsp[[:space:]]*150[-[:space:]]*xg([0-9a-z]+) ]]; then
      model="FSP150-XG${BASH_REMATCH[1]^^}"
    elif [[ "$lower" =~ fsp150[-[:space:]]*xg([0-9a-z]+) ]]; then
      model="FSP150-XG${BASH_REMATCH[1]^^}"
    elif [[ "$lower" =~ optiswitch[[:space:]]+([a-z0-9-]+) ]]; then
      model="OptiSwitch ${BASH_REMATCH[1]^^}"
    elif [[ "$lower" =~ waveserver-ai ]]; then
      model="Waveserver-Ai"
    elif [[ "$lower" =~ t-marc[[:space:]]*([0-9]+) ]]; then
      model="T-Marc ${BASH_REMATCH[1]}"
    elif [[ "$lower" =~ t5c-xg ]]; then
      model="T5C-XG"
    else
      model="Ciena Unknown"
    fi

  elif [[ "$lower" =~ cisco ]]; then
    family="Cisco"
    if [[ "$lower" =~ (isr[[:space:]]?[0-9a-z-]+) ]]; then
      model="${BASH_REMATCH[1]^^}"
    else
      model="Cisco Unknown"
    fi

  elif [[ "$lower" =~ smartoptics ]]; then
    family="Smartoptics"
    if [[ "$lower" =~ (dcp-[a-z0-9+-]+) ]]; then
      model="${BASH_REMATCH[1]^^}"
    else
      model="Smartoptics Unknown"
    fi

  elif [[ "$lower" =~ mini-link ]]; then
    family="Ericsson"
    if [[ "$lower" =~ (mini-link[[:space:]][0-9/]+) ]]; then
      token="${BASH_REMATCH[1]}"
      model="${token^^}"
    else
      model="MINI-LINK"
    fi

  elif [[ "$lower" =~ linux ]]; then
    family="Linux"
    if [[ "$lower" =~ machine:([a-z0-9_/-]+) ]]; then
      model="Linux ${BASH_REMATCH[1]^^}"
    else
      model="Linux"
    fi
  fi

  printf '%s|%s' "$(normalize_word "$family")" "$(normalize_word "$model")"
}

parse_args() {
  while (($#)); do
    case "$1" in
      -i|--cidr-file)
        shift || die "Missing value for --cidr-file."
        CIDR_FILE="${1:-}"
        ;;
      -c|--community-file)
        shift || die "Missing value for --community-file."
        COMMUNITY_FILE="${1:-}"
        ;;
      -o|--output-dir)
        shift || die "Missing value for --output-dir."
        OUTPUT_DIR="${1:-}"
        ;;
      --snmp-jobs)
        shift || die "Missing value for --snmp-jobs."
        MAX_SNMP_JOBS="${1:-}"
        ;;
      --fping-retries)
        shift || die "Missing value for --fping-retries."
        FPING_RETRIES="${1:-}"
        ;;
      --fping-timeout)
        shift || die "Missing value for --fping-timeout."
        FPING_TIMEOUT_MS="${1:-}"
        ;;
      --snmp-retries)
        shift || die "Missing value for --snmp-retries."
        SNMP_RETRIES="${1:-}"
        ;;
      --snmp-timeout)
        shift || die "Missing value for --snmp-timeout."
        SNMP_TIMEOUT_SEC="${1:-}"
        ;;
      --no-snmp)
        NO_SNMP=1
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      --)
        shift
        while (($#)); do
          add_cidr "$1"
          shift
        done
        return
        ;;
      -*)
        die "Unknown option: $1"
        ;;
      *)
        add_cidr "$1"
        ;;
    esac
    shift || true
  done
}

validate_numeric_options() {
  [[ "$MAX_SNMP_JOBS" =~ ^[0-9]+$ ]] || die "--snmp-jobs must be a number."
  [[ "$FPING_RETRIES" =~ ^[0-9]+$ ]] || die "--fping-retries must be a number."
  [[ "$FPING_TIMEOUT_MS" =~ ^[0-9]+$ ]] || die "--fping-timeout must be a number."
  [[ "$SNMP_RETRIES" =~ ^[0-9]+$ ]] || die "--snmp-retries must be a number."
  [[ "$SNMP_TIMEOUT_SEC" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "--snmp-timeout must be a number."
  (( MAX_SNMP_JOBS >= 1 )) || die "--snmp-jobs must be at least 1."
}

load_cidrs() {
  local line

  if [[ -n "$CIDR_FILE" ]]; then
    [[ -f "$CIDR_FILE" ]] || die "CIDR file not found: $CIDR_FILE"
    while IFS= read -r line || [[ -n "$line" ]]; do
      add_cidr "$line"
    done < "$CIDR_FILE"
  fi

  if (( ${#CIDRS[@]} == 0 )); then
    if [[ -t 0 ]]; then
      printf 'Paste CIDR blocks, one per line. Press Ctrl-D when finished.\n'
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
      add_cidr "$line"
    done
  fi

  (( ${#CIDRS[@]} > 0 )) || die "No CIDR blocks provided."
}

check_dependencies() {
  local missing=()
  local cmd

  for cmd in awk sed sort mktemp date wc tr; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done

  command -v fping >/dev/null 2>&1 || missing+=("fping")
  if (( NO_SNMP == 0 )); then
    command -v snmpget >/dev/null 2>&1 || missing+=("snmpget")
  fi

  if (( ${#missing[@]} > 0 )); then
    printf 'Missing required command(s): %s\n' "${missing[*]}" >&2
    printf 'On Ubuntu, install the network tools with:\n' >&2
    printf '  sudo apt-get update && sudo apt-get install -y fping snmp\n' >&2
    exit 1
  fi
}

load_communities() {
  local line

  (( NO_SNMP == 1 )) && return 0
  community_file_has_values "$COMMUNITY_FILE" || die "Community file missing or empty: $COMMUNITY_FILE"

  COMMUNITIES=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="$(trim "$line")"
    [[ -z "$line" ]] && continue
    [[ "${line:0:1}" == "#" ]] && continue
    COMMUNITIES+=("$line")
  done < "$COMMUNITY_FILE"

  (( ${#COMMUNITIES[@]} > 0 )) || die "No usable community strings found in $COMMUNITY_FILE"
}

setup_outputs() {
  mkdir -p "$OUTPUT_DIR"

  RUN_LOG="${OUTPUT_DIR}/run_log_${STAMP}.txt"
  ERROR_LOG="${OUTPUT_DIR}/scan_errors_${STAMP}.log"
  ALIVE_CSV="${OUTPUT_DIR}/alive_ips_by_subnet_${STAMP}.csv"
  DETAIL_CSV="${OUTPUT_DIR}/snmp_inventory_detail_${STAMP}.csv"
  SUBNET_SUMMARY_CSV="${OUTPUT_DIR}/snmp_summary_subnet_totals_${STAMP}.csv"
  MODEL_SUMMARY_CSV="${OUTPUT_DIR}/snmp_summary_subnet_model_${STAMP}.csv"
  TMP_DIR="$(mktemp -d "${OUTPUT_DIR}/.work_${STAMP}_XXXXXX")"

  : > "$RUN_LOG"
  : > "$ERROR_LOG"

  trap 'rm -rf "${TMP_DIR:-}"' EXIT
}

discover_alive_ips() {
  local raw_pairs="${TMP_DIR}/alive_pairs.raw.csv"
  local sorted_pairs="${TMP_DIR}/alive_pairs.sorted.csv"
  local cidr cidr_tmp cidr_err count ip

  : > "$raw_pairs"

  section "Step 2/5 - Running fping against ${#CIDRS[@]} CIDR block(s)"
  for cidr in "${CIDRS[@]}"; do
    cidr_tmp="${TMP_DIR}/fping_$(printf '%s' "$cidr" | tr '/.' '__').txt"
    cidr_err="${TMP_DIR}/fping_$(printf '%s' "$cidr" | tr '/.' '__').err"

    log "Pinging ${cidr} with fping..."
    fping -a -g -r "$FPING_RETRIES" -t "$FPING_TIMEOUT_MS" "$cidr" > "$cidr_tmp" 2> "$cidr_err" || true

    if [[ -s "$cidr_err" ]]; then
      sed "s/^/[${cidr}] /" "$cidr_err" >> "$ERROR_LOG"
    fi

    count=0
    while IFS= read -r ip || [[ -n "$ip" ]]; do
      ip="$(trim "$ip")"
      [[ -z "$ip" ]] && continue
      if is_ipv4 "$ip"; then
        printf '%s,%s\n' "$cidr" "$ip" >> "$raw_pairs"
        (( count += 1 ))
      fi
    done < "$cidr_tmp"

    log "CIDR ${cidr}: ${count} alive IP(s)"
  done

  sort -u -t, -k1,1 -k2,2V "$raw_pairs" > "$sorted_pairs"

  csv_row "subnet" "ip_address" > "$ALIVE_CSV"
  while IFS=, read -r cidr ip || [[ -n "${cidr:-}" ]]; do
    [[ -z "${cidr:-}" || -z "${ip:-}" ]] && continue
    csv_row "$cidr" "$ip" >> "$ALIVE_CSV"
  done < "$sorted_pairs"

  ALIVE_PAIRS_FILE="$sorted_pairs"
}

has_useful_snmp_value() {
  local value="${1:-}"
  [[ -z "$value" || "$value" == "NA" ]] && return 1
  [[ "$value" =~ ^No[[:space:]]Such ]] && return 1
  [[ "$value" =~ ^Timeout ]] && return 1
  [[ "$value" =~ ^No[[:space:]]Response ]] && return 1
  return 0
}

process_snmp_target() {
  local subnet="$1"
  local ip="$2"
  local ordinal="$3"
  local total="$4"
  local result_file="$5"
  local snmp_status="NO_SNMP"
  local community_match="none"
  local sys_object_id="NA"
  local sys_descr="NA"
  local sys_contact="NA"
  local sys_name="NA"
  local sys_location="NA"
  local family="Unknown"
  local model="Unknown"
  local combined classification community idx snmp_output
  local -a lines=()
  local -a snmp_oids=(
    ".1.3.6.1.2.1.1.2.0"
    ".1.3.6.1.2.1.1.1.0"
    ".1.3.6.1.2.1.1.4.0"
    ".1.3.6.1.2.1.1.5.0"
    ".1.3.6.1.2.1.1.6.0"
  )

  if (( NO_SNMP == 0 )); then
    for idx in "${!COMMUNITIES[@]}"; do
      community="${COMMUNITIES[$idx]}"
      snmp_output="$(snmpget -v2c -c "$community" -r "$SNMP_RETRIES" -t "$SNMP_TIMEOUT_SEC" -Oqv "$ip" "${snmp_oids[@]}" 2>/dev/null || true)"
      [[ -z "$snmp_output" ]] && continue

      mapfile -t lines <<< "$snmp_output"
      sys_object_id="$(clean_snmp_value "${lines[0]:-NA}")"
      sys_descr="$(clean_snmp_value "${lines[1]:-NA}")"
      sys_contact="$(clean_snmp_value "${lines[2]:-NA}")"
      sys_name="$(clean_snmp_value "${lines[3]:-NA}")"
      sys_location="$(clean_snmp_value "${lines[4]:-NA}")"

      if has_useful_snmp_value "$sys_object_id" || has_useful_snmp_value "$sys_descr" || has_useful_snmp_value "$sys_name"; then
        snmp_status="OK"
        community_match="community_$((idx + 1))"
        break
      fi
    done
  else
    snmp_status="SKIPPED"
    community_match="not_run"
  fi

  if [[ "$snmp_status" == "OK" ]]; then
    classification="$(classify_device "$sys_object_id" "$sys_descr")"
    family="${classification%%|*}"
    model="${classification#*|}"
    printf '[%s/%s] %s %s -> SNMP OK (%s %s)\n' "$ordinal" "$total" "$subnet" "$ip" "$family" "$model"
  elif [[ "$snmp_status" == "SKIPPED" ]]; then
    printf '[%s/%s] %s %s -> SNMP skipped\n' "$ordinal" "$total" "$subnet" "$ip"
  else
    printf '[%s/%s] %s %s -> no SNMP response\n' "$ordinal" "$total" "$subnet" "$ip"
  fi

  combined="${sys_object_id} ${sys_descr} ${sys_name}"
  if [[ "$snmp_status" != "OK" ]]; then
    printf '[%s] %s %s: %s\n' "$(date +"%H:%M:%S")" "$subnet" "$ip" "$snmp_status" >> "$ERROR_LOG"
  elif [[ "$combined" =~ No[[:space:]]Such ]]; then
    printf '[%s] %s %s: SNMP returned one or more missing OIDs\n' "$(date +"%H:%M:%S")" "$subnet" "$ip" >> "$ERROR_LOG"
  fi

  csv_row \
    "$subnet" \
    "$ip" \
    "alive" \
    "$snmp_status" \
    "$community_match" \
    "$family" \
    "$model" \
    "$sys_name" \
    "$sys_object_id" \
    "$sys_descr" \
    "$sys_contact" \
    "$sys_location" \
    > "$result_file"
}

run_snmp_inventory() {
  local alive_pairs_file="$1"
  local result_dir="${TMP_DIR}/snmp_results"
  local detail_unsorted="${TMP_DIR}/snmp_inventory.unsorted.csv"
  local total counter subnet ip result_file
  local -a result_files=()

  mkdir -p "$result_dir"

  total="$(wc -l < "$alive_pairs_file" | tr -d ' ')"
  csv_row \
    "subnet" \
    "ip_address" \
    "ping_status" \
    "snmp_status" \
    "community_match" \
    "device_family" \
    "device_model" \
    "sysName" \
    "sysObjectID" \
    "sysDescr" \
    "sysContact" \
    "sysLocation" \
    > "$detail_unsorted"

  if (( total == 0 )); then
    cp "$detail_unsorted" "$DETAIL_CSV"
    log "No alive IPs found, so SNMP inventory was skipped."
    return 0
  fi

  if (( NO_SNMP == 1 )); then
    section "Step 3/5 - Writing alive-only inventory for ${total} IP(s)"
  else
    section "Step 3/5 - SNMP polling ${total} alive IP(s) with ${#COMMUNITIES[@]} community candidate(s)"
  fi

  counter=0
  while IFS=, read -r subnet ip || [[ -n "${subnet:-}" ]]; do
    [[ -z "${subnet:-}" || -z "${ip:-}" ]] && continue
    (( counter += 1 ))
    result_file="${result_dir}/$(printf '%08d' "$counter").csv"

    process_snmp_target "$subnet" "$ip" "$counter" "$total" "$result_file" &

    if (( counter % 25 == 0 )); then
      log "Queued ${counter}/${total} SNMP target(s). Active jobs: $(jobs -rp | wc -l | tr -d ' ')"
    fi

    while (( $(jobs -rp | wc -l | tr -d ' ') >= MAX_SNMP_JOBS )); do
      sleep 0.2
    done
  done < "$alive_pairs_file"

  wait

  result_files=("${result_dir}"/*.csv)
  if [[ -e "${result_files[0]:-}" ]]; then
    cat "${result_files[@]}" >> "$detail_unsorted"
  fi

  {
    head -n 1 "$detail_unsorted"
    tail -n +2 "$detail_unsorted" | sort -t, -k1,1 -k2,2V
  } > "$DETAIL_CSV"

  log "Detailed CSV sorted by subnet and IP."
}

build_summaries() {
  local subnet_tmp="${TMP_DIR}/summary_by_subnet.tmp.csv"
  local model_tmp="${TMP_DIR}/summary_by_subnet_model.tmp.csv"
  local capacity_file="${TMP_DIR}/cidr_capacity.csv"
  local cidr

  section "Step 4/5 - Building executive summary CSVs"

  : > "$capacity_file"
  for cidr in "${CIDRS[@]}"; do
    printf '%s,%s\n' "$cidr" "$(cidr_usable_ips "$cidr")" >> "$capacity_file"
  done

  {
    csv_row \
      "subnet" \
      "total_usable_ips" \
      "used_ips" \
      "free_ips" \
      "used_percent" \
      "free_percent" \
      "snmp_success" \
      "snmp_failed_or_skipped" \
      "snmp_success_percent"
    awk -F, '
      FNR == NR {
        total[$1]=$2
        next
      }
      NF >= 7 {
        subnet=$1
        used[subnet]++
        if ($4 == "OK") {
          ok[subnet]++
        } else {
          failed[subnet]++
        }
      }
      END {
        for (subnet in total) {
          usable = total[subnet] + 0
          used_count = used[subnet] + 0
          free_count = usable - used_count
          if (free_count < 0) {
            free_count = 0
          }
          used_percent = usable ? (used_count * 100 / usable) : 0
          free_percent = usable ? (free_count * 100 / usable) : 0
          snmp_percent = used_count ? (ok[subnet] * 100 / used_count) : 0
          printf "%s,%d,%d,%d,%.1f%%,%.1f%%,%d,%d,%.1f%%\n", subnet, usable, used_count, free_count, used_percent, free_percent, ok[subnet] + 0, failed[subnet] + 0, snmp_percent
        }
      }
    ' "$capacity_file" <(tail -n +2 "$DETAIL_CSV") | sort -t, -k1,1
  } > "$subnet_tmp"
  mv "$subnet_tmp" "$SUBNET_SUMMARY_CSV"

  {
    csv_row \
      "subnet" \
      "total_usable_ips" \
      "used_ips" \
      "free_ips" \
      "used_percent" \
      "free_percent" \
      "snmp_success" \
      "snmp_failed_or_skipped" \
      "device_family" \
      "device_model" \
      "device_count" \
      "percent_of_snmp_success"
    awk -F, '
      FNR == NR {
        total[$1]=$2
        next
      }
      NF >= 7 {
        subnet=$1
        status=$4
        family=$6
        model=$7
        used[subnet]++
        if (status == "OK") {
          ok[subnet]++
          key=subnet SUBSEP family SUBSEP model
          count[key]++
          has_model[subnet]=1
        } else {
          failed[subnet]++
        }
      }
      END {
        for (key in count) {
          split(key, parts, SUBSEP)
          subnet=parts[1]
          family=parts[2]
          model=parts[3]
          usable = total[subnet] + 0
          used_count = used[subnet] + 0
          free_count = usable - used_count
          if (free_count < 0) {
            free_count = 0
          }
          used_percent = usable ? (used_count * 100 / usable) : 0
          free_percent = usable ? (free_count * 100 / usable) : 0
          percent = ok[subnet] ? (count[key] * 100 / ok[subnet]) : 0
          printf "%s,%d,%d,%d,%.1f%%,%.1f%%,%d,%d,%s,%s,%d,%.1f%%\n", subnet, usable, used_count, free_count, used_percent, free_percent, ok[subnet] + 0, failed[subnet] + 0, family, model, count[key], percent
        }
        for (subnet in total) {
          if (!(subnet in has_model)) {
            usable = total[subnet] + 0
            used_count = used[subnet] + 0
            free_count = usable - used_count
            if (free_count < 0) {
              free_count = 0
            }
            used_percent = usable ? (used_count * 100 / usable) : 0
            free_percent = usable ? (free_count * 100 / usable) : 0
            printf "%s,%d,%d,%d,%.1f%%,%.1f%%,0,%d,No SNMP,No SNMP Response,0,0.0%%\n", subnet, usable, used_count, free_count, used_percent, free_percent, failed[subnet] + 0
          }
        }
      }
    ' "$capacity_file" <(tail -n +2 "$DETAIL_CSV") | sort -t, -k1,1 -k9,9 -k10,10
  } > "$model_tmp"
  mv "$model_tmp" "$MODEL_SUMMARY_CSV"

  log "Subnet summary CSV: ${SUBNET_SUMMARY_CSV}"
  log "Model summary CSV : ${MODEL_SUMMARY_CSV}"
}

print_final_report() {
  local total_alive
  local total_success

  total_alive="$(tail -n +2 "$DETAIL_CSV" | wc -l | tr -d ' ')"
  total_success="$(tail -n +2 "$DETAIL_CSV" | awk -F, '$4 == "OK" {count++} END {print count + 0}')"

  section "Step 5/5 - Scan complete"
  log "CIDR blocks processed : ${#CIDRS[@]}"
  log "Alive IP rows         : ${total_alive}"
  log "SNMP success rows     : ${total_success}"
  log "Output folder         : ${OUTPUT_DIR}"
  log "Alive CSV             : ${ALIVE_CSV}"
  log "Detailed CSV          : ${DETAIL_CSV}"
  log "Subnet summary CSV    : ${SUBNET_SUMMARY_CSV}"
  log "Model summary CSV     : ${MODEL_SUMMARY_CSV}"
  log "Run log               : ${RUN_LOG}"
  log "Error log             : ${ERROR_LOG}"
}

main() {
  parse_args "$@"
  validate_numeric_options
  ensure_community_file_ready
  load_cidrs
  setup_outputs

  section "Step 1/5 - Starting CIDR fping + SNMP audit"
  log "Script version        : ${SCRIPT_VERSION}"
  log "CIDR blocks queued    : ${#CIDRS[@]}"
  log "Community file        : ${COMMUNITY_FILE}"
  log "Output folder         : ${OUTPUT_DIR}"
  log "Parallel SNMP jobs    : ${MAX_SNMP_JOBS}"
  log "fping timeout/retries : ${FPING_TIMEOUT_MS}ms / ${FPING_RETRIES}"
  log "SNMP timeout/retries  : ${SNMP_TIMEOUT_SEC}s / ${SNMP_RETRIES}"
  log "Community strings are intentionally not printed or exported."

  check_dependencies
  load_communities
  if (( NO_SNMP == 0 )); then
    log "Loaded ${#COMMUNITIES[@]} community candidate(s)."
  else
    log "SNMP polling disabled by --no-snmp."
  fi

  discover_alive_ips
  run_snmp_inventory "$ALIVE_PAIRS_FILE"
  build_summaries
  print_final_report
}

main "$@"
