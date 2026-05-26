#!/usr/bin/env bash

snmp_walker_bool_is_off() {
  case "${1:-}" in
    0|false|False|FALSE|no|No|NO|off|Off|OFF) return 0 ;;
    *) return 1 ;;
  esac
}

snmp_walker_bool_is_on() {
  case "${1:-}" in
    1|true|True|TRUE|yes|Yes|YES|on|On|ON) return 0 ;;
    *) return 1 ;;
  esac
}

snmp_walker_is_wsl() {
  grep -qiE "microsoft|wsl" /proc/sys/kernel/osrelease 2>/dev/null
}

snmp_walker_default_venv_dir() {
  local current_dir
  current_dir="$(pwd -P)"
  if snmp_walker_is_wsl; then
    case "$current_dir" in
      /mnt/*)
        local repo_name
        local repo_key
        repo_name="${current_dir##*/}"
        repo_key="$(printf '%s' "$current_dir" | cksum | cut -d ' ' -f 1)"
        printf '%s\n' "${XDG_CACHE_HOME:-$HOME/.cache}/snmp-walker/venvs/${repo_name}-${repo_key}"
        return 0
        ;;
    esac
  fi
  printf '%s\n' ".venv"
}

snmp_walker_default_tools_dir() {
  local current_dir
  current_dir="$(pwd -P)"
  if snmp_walker_is_wsl; then
    case "$current_dir" in
      /mnt/*)
        printf '%s\n' "${XDG_CACHE_HOME:-$HOME/.cache}/snmp-walker/tools"
        return 0
        ;;
    esac
  fi
  printf '%s\n' ".tools"
}

snmp_walker_find_uv() {
  if [ -n "${SNMP_WALKER_UV:-}" ] && [ -x "$SNMP_WALKER_UV" ]; then
    printf '%s\n' "$SNMP_WALKER_UV"
    return 0
  fi

  if command -v uv >/dev/null 2>&1; then
    command -v uv
    return 0
  fi

  local tools_dir="${SNMP_WALKER_TOOLS_DIR:-$(snmp_walker_default_tools_dir)}"
  local local_uv="$tools_dir/uv/uv"
  if [ -x "$local_uv" ]; then
    printf '%s\n' "$local_uv"
    return 0
  fi

  return 1
}

snmp_walker_install_uv() {
  if snmp_walker_bool_is_off "${SNMP_WALKER_UV_AUTO_INSTALL:-1}"; then
    return 1
  fi

  local tools_dir="${SNMP_WALKER_TOOLS_DIR:-$(snmp_walker_default_tools_dir)}"
  local install_dir="$tools_dir/uv"
  local install_url="${SNMP_WALKER_UV_INSTALL_URL:-https://astral.sh/uv/install.sh}"

  mkdir -p "$install_dir"
  echo "Installing uv locally to $install_dir so no system Python venv package is needed..." >&2

  if command -v curl >/dev/null 2>&1; then
    curl -LsSf "$install_url" | env UV_UNMANAGED_INSTALL="$install_dir" sh >&2
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "$install_url" | env UV_UNMANAGED_INSTALL="$install_dir" sh >&2
  else
    echo "Could not download uv because neither curl nor wget is installed." >&2
    return 1
  fi

  if [ -x "$install_dir/uv" ]; then
    printf '%s\n' "$install_dir/uv"
    return 0
  fi

  echo "The uv installer finished, but $install_dir/uv was not found." >&2
  return 1
}

snmp_walker_get_uv() {
  snmp_walker_find_uv || snmp_walker_install_uv
}

snmp_walker_create_venv() {
  local venv_log
  venv_log="$(mktemp "${TMPDIR:-/tmp}/snmp-walker-venv.XXXXXX")"
  mkdir -p "$(dirname "$VENV_DIR")"

  if "$PYTHON_BIN" -m venv "$VENV_DIR" >"$venv_log" 2>&1; then
    rm -f "$venv_log"
    return 0
  fi

  echo "Python venv creation did not fully complete." >&2
  if [ -x "$VENV_PYTHON" ]; then
    echo "$VENV_DIR has a Python interpreter, so the launcher will use uv for dependency install if pip is missing." >&2
    rm -f "$venv_log"
    return 0
  fi

  if ! snmp_walker_bool_is_off "${SNMP_WALKER_UV_AUTO_INSTALL:-1}"; then
    echo "Trying uv fallback to create $VENV_DIR without sudo..." >&2
    local uv_bin
    if uv_bin="$(snmp_walker_get_uv)" && "$uv_bin" venv --python "$PYTHON_BIN" "$VENV_DIR"; then
      rm -f "$venv_log"
      return 0
    fi
  fi

  echo "Could not create $VENV_DIR with Python venv or uv." >&2
  echo "Original Python venv error:" >&2
  sed 's/^/  /' "$venv_log" >&2
  rm -f "$venv_log"
  return 1
}

snmp_walker_ensure_venv() {
  if [ ! -d "$VENV_DIR" ]; then
    snmp_walker_create_venv
  fi

  if [ ! -x "$VENV_PYTHON" ]; then
    echo "$VENV_DIR does not look like a Linux/WSL virtual environment." >&2
    echo "Use SNMP_WALKER_VENV=.venv-wsl, or remove the incompatible venv." >&2
    exit 1
  fi
}

snmp_walker_source_signature() {
  find README.md pyproject.toml requirements.txt snmp_walker -type f 2>/dev/null \
    ! -path '*/__pycache__/*' \
    ! -name '*.pyc' \
    ! -name '*.pyo' \
    | LC_ALL=C sort \
    | while IFS= read -r source_file; do
        cksum "$source_file"
      done \
    | cksum \
    | cut -d ' ' -f 1
}

snmp_walker_prepare_install_source() {
  if snmp_walker_bool_is_on "${SNMP_WALKER_EDITABLE:-0}"; then
    printf '%s\n' "."
    return 0
  fi

  local current_dir
  current_dir="$(pwd -P)"
  if ! snmp_walker_is_wsl; then
    printf '%s\n' "."
    return 0
  fi

  case "$current_dir" in
    /mnt/*) ;;
    *)
      printf '%s\n' "."
      return 0
      ;;
  esac

  local signature
  local cache_root
  local build_dir
  local temp_dir
  signature="$(snmp_walker_source_signature)"
  cache_root="${XDG_CACHE_HOME:-$HOME/.cache}/snmp-walker/build-src"
  build_dir="$cache_root/$signature"
  temp_dir="$cache_root/.tmp-$signature-$$"

  if [ ! -f "$build_dir/pyproject.toml" ]; then
    mkdir -p "$cache_root"
    rm -rf "$temp_dir"
    mkdir -p "$temp_dir"
    tar -cf - README.md pyproject.toml requirements.txt snmp_walker | tar -C "$temp_dir" -xf -
    rm -rf "$build_dir"
    mv "$temp_dir" "$build_dir"
  fi

  printf '%s\n' "$build_dir"
}

snmp_walker_needs_install() {
  if [ "${SNMP_WALKER_FORCE_INSTALL:-0}" = "1" ]; then
    return 0
  fi
  if [ "${SNMP_WALKER_SKIP_INSTALL:-0}" = "1" ]; then
    return 1
  fi
  if [ ! -f "$INSTALL_STAMP" ]; then
    return 0
  fi

  local signature_file
  local current_signature
  local installed_signature
  signature_file="$VENV_DIR/.snmp-walker-source-signature"
  current_signature="$(snmp_walker_source_signature)"
  installed_signature="$(cat "$signature_file" 2>/dev/null || true)"
  if [ "$current_signature" != "$installed_signature" ]; then
    return 0
  fi
  return 1
}

snmp_walker_install_project() {
  if ! snmp_walker_needs_install; then
    return 0
  fi

  local -a install_args
  local install_source
  install_source="$(snmp_walker_prepare_install_source)"
  install_args=("$install_source")
  if snmp_walker_bool_is_on "${SNMP_WALKER_EDITABLE:-0}"; then
    install_args=("-e" ".")
  fi

  if "$VENV_PYTHON" -m pip --version >/dev/null 2>&1; then
    if [ "${SNMP_WALKER_UPGRADE_PIP:-0}" = "1" ]; then
      "$VENV_PYTHON" -m pip install --upgrade pip
    fi
    "$VENV_PYTHON" -m pip install "${install_args[@]}"
  else
    echo "$VENV_DIR does not have pip; installing dependencies with local uv instead." >&2
    local uv_bin
    uv_bin="$(snmp_walker_get_uv)" || {
      echo "Could not find or install uv. Install python3-venv/python3-pip or set SNMP_WALKER_UV=/path/to/uv." >&2
      exit 1
    }
    UV_LINK_MODE="${UV_LINK_MODE:-copy}" "$uv_bin" pip install --python "$VENV_PYTHON" "${install_args[@]}"
  fi

  snmp_walker_source_signature > "$VENV_DIR/.snmp-walker-source-signature"
  touch "$INSTALL_STAMP"
}
