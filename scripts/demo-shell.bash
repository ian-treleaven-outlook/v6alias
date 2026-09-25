#!/usr/bin/env bash
# Session-only Bash helpers; source this file, then explicitly enable:
#   source ~/v6alias/demo-shell.bash
#   v6alias-demo-on --color "/path/to/v6alias" "/path/to/v6alias.yaml"
# Usage: v6alias-demo-on [--color] [BINARY [CONFIG]]
# Defaults: executable beside this script, otherwise ../dist/linux-x64/v6alias;
# CONFIG defaults to v6alias.yaml beside the selected executable.
# Relative paths are pinned to absolute paths when enabled. Nothing is installed,
# exported to child shells, or written to PATH, profiles, config, or TERM.
# Alias FIRST: ping corp:42 -c 3; ssh corp:42 -l scout-user
# Rust --dry-run is recognized before the first --; everything after -- is native:
#   ping corp:42 --dry-run -- -c 3
# ifconfig forwards to interfaces (e.g. --raw, --json, --interface eth0).
# Native commands never accept alias syntax: native-ping ::1; native-ssh host.
# --color forces CLI color and adds a reversible colored user@host prompt.
# Otherwise CLI color is auto (honoring NO_COLOR); the prompt is unchanged.
# JSON color handling belongs to the CLI and remains plain even with --color.
# v6alias-demo-off removes only unchanged functions installed by this script.

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    printf 'Source this script in Bash, then run v6alias-demo-on [--color] [BINARY [CONFIG]].\n' >&2
    exit 2
fi
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 2) )); then
    printf 'demo-shell.bash requires Bash 4.2 or newer.\n' >&2
    return 2
fi
if [[ ${_V6ALIAS_DEMO_LOADED:-} == 1 ]]; then
    return 0
fi

function _v6alias_demo_absolute {
    local path=$1 directory=.
    [[ $path != */* ]] || directory=${path%/*}
    directory=$(CDPATH= builtin cd -- "${directory:-/}" && builtin pwd -P) || return
    printf '%s/%s\n' "${directory%/}" "${path##*/}"
}

_V6ALIAS_DEMO_SOURCE=$(_v6alias_demo_absolute "${BASH_SOURCE[0]}") || return
declare -gA _V6ALIAS_DEMO_FUNCTIONS=() _V6ALIAS_DEMO_NATIVE=()
declare -ga _V6ALIAS_DEMO_NAMES=(
    ping trace traceroute tracert ssh ifconfig
    native-ping native-trace native-ssh native-ifconfig
)
_V6ALIAS_DEMO_ACTIVE=0

function _v6alias_demo_network {
    local tool=$1 target part
    shift
    if (( $# == 0 )); then
        "$_V6ALIAS_DEMO_BINARY" --config "$_V6ALIAS_DEMO_CONFIG" \
            --color "$_V6ALIAS_DEMO_COLOR" "$tool" --help
        return $?
    fi
    target=$1
    shift
    # Match the Rust alias grammar, including canonical decimal and u16 bounds,
    # before anything can invoke the binary. Unknown profiles remain CLI errors.
    if [[ ! $target =~ ^[a-z0-9-]+:([0-9]+\.)?[0-9]+$ ]]; then
        printf '%s: alias must come first (e.g. corp:42); use native-%s for hosts/IPs.\n' "$tool" "$tool" >&2
        return 2
    fi
    local address=${target#*:} device=${target##*[.:]}
    local -a numbers=("${address%%.*}" "$device") native_args=() dry_run=()
    for part in "${numbers[@]}"; do
        if (( ${#part} > 5 )) || [[ $part == 0?* ]] || (( 10#$part > 65535 )); then
            printf '%s: alias numbers must be unpadded decimal in 0..65535.\n' "$tool" >&2
            return 2
        fi
    done
    if [[ $device == 0 ]]; then
        printf '%s: alias device 0 is reserved.\n' "$tool" >&2
        return 2
    fi
    while (( $# )); do
        case $1 in
            --dry-run) dry_run=(--dry-run); shift ;;
            --) shift; native_args+=("$@"); break ;;
            *) native_args+=("$1"); shift ;;
        esac
    done
    "$_V6ALIAS_DEMO_BINARY" --config "$_V6ALIAS_DEMO_CONFIG" \
        --color "$_V6ALIAS_DEMO_COLOR" "$tool" "$target" \
        "${dry_run[@]}" -- "${native_args[@]}"
}

function _v6alias_demo_native {
    local tool=$1 executable=${_V6ALIAS_DEMO_NATIVE[$1]-}
    shift
    if [[ -z $executable ]]; then
        printf 'native-%s: native executable was not found in PATH when enabled.\n' "$tool" >&2
        return 127
    fi
    command "$executable" "$@"
}

function v6alias-demo-on {
    local color=auto binary config name executable candidate
    if [[ ${1-} == --help ]]; then
        printf 'Usage: v6alias-demo-on [--color] [BINARY [CONFIG]]; v6alias-demo-off to restore.\n'
        return 0
    fi
    if [[ ${1-} == --color ]]; then color=always; shift; fi
    if (( $# > 2 )) || [[ ${1-} == -* ]]; then
        printf 'Usage: v6alias-demo-on [--color] [BINARY [CONFIG]]\n' >&2
        return 2
    fi
    binary=${_V6ALIAS_DEMO_SOURCE%/*}/v6alias
    if [[ ! -x $binary ]]; then
        binary=${_V6ALIAS_DEMO_SOURCE%/*}/../dist/linux-x64/v6alias
    fi
    binary=$(_v6alias_demo_absolute "${1-$binary}") || return
    config=$(_v6alias_demo_absolute "${2-${binary%/*}/v6alias.yaml}") || return
    if [[ ! -f $binary || ! -x $binary || ! -f $config || ! -r $config ]]; then
        printf 'Demo needs an executable BINARY and readable CONFIG: %s ; %s\n' "$binary" "$config" >&2
        return 2
    fi
    if [[ $_V6ALIAS_DEMO_ACTIVE == 1 ]]; then
        if [[ $binary != "$_V6ALIAS_DEMO_BINARY" || $config != "$_V6ALIAS_DEMO_CONFIG" || $color != "$_V6ALIAS_DEMO_COLOR" ]]; then
            printf 'Demo already active with different settings; run v6alias-demo-off first.\n' >&2
            return 2
        fi
        for name in "${_V6ALIAS_DEMO_NAMES[@]}"; do
            if [[ $(declare -f -- "$name") != "${_V6ALIAS_DEMO_FUNCTIONS[$name]}" ]]; then
                printf 'Demo function changed: %s; run v6alias-demo-off first.\n' "$name" >&2
                return 2
            fi
        done
        printf 'v6alias DEMO already ready.\n'
        return 0
    fi
    # Preflight every name before creating any wrapper; PATH executables are OK.
    for name in "${_V6ALIAS_DEMO_NAMES[@]}"; do
        if alias "$name" &>/dev/null || declare -F -- "$name" >/dev/null; then
            printf 'Demo not enabled: existing alias/function %s (nothing replaced).\n' "$name" >&2
            return 2
        fi
    done
    _V6ALIAS_DEMO_NATIVE=()
    for name in ping trace ssh ifconfig; do
        executable=
        if [[ $name == trace ]]; then
            for candidate in traceroute tracert; do
                if executable=$(type -P -- "$candidate"); then break; fi
            done
        else
            executable=$(type -P -- "$name") || executable=
        fi
        if [[ -n $executable ]]; then
            executable=$(_v6alias_demo_absolute "$executable") || return
        fi
        _V6ALIAS_DEMO_NATIVE[$name]=$executable
    done
    _V6ALIAS_DEMO_BINARY=$binary
    _V6ALIAS_DEMO_CONFIG=$config
    _V6ALIAS_DEMO_COLOR=$color
    _V6ALIAS_DEMO_PS1_SET=${PS1+x}
    _V6ALIAS_DEMO_PS1=${PS1-}

    # The function keyword prevents existing aliases from expanding at source time.
    function ping { _v6alias_demo_network ping "$@"; }
    function trace { _v6alias_demo_network trace "$@"; }
    function traceroute { _v6alias_demo_network trace "$@"; }
    function tracert { _v6alias_demo_network trace "$@"; }
    function ssh { _v6alias_demo_network ssh "$@"; }
    function ifconfig {
        "$_V6ALIAS_DEMO_BINARY" --config "$_V6ALIAS_DEMO_CONFIG" \
            --color "$_V6ALIAS_DEMO_COLOR" interfaces "$@"
    }
    function native-ping { _v6alias_demo_native ping "$@"; }
    function native-trace { _v6alias_demo_native trace "$@"; }
    function native-ssh { _v6alias_demo_native ssh "$@"; }
    function native-ifconfig { _v6alias_demo_native ifconfig "$@"; }
    for name in "${_V6ALIAS_DEMO_NAMES[@]}"; do
        _V6ALIAS_DEMO_FUNCTIONS[$name]=$(declare -f -- "$name")
        export -n -f "$name"
    done
    if [[ $color == always ]]; then
        PS1='\[\e[1;36m\]\u@\h\[\e[0m\]:\w\$ '
    fi
    _V6ALIAS_DEMO_ACTIVE=1
    printf 'v6alias DEMO ready: ping/trace/ssh ALIAS [native options]; ifconfig lists interfaces.\n'
    printf 'Native escapes: native-ping, native-trace, native-ssh, native-ifconfig. Undo: v6alias-demo-off.\n'
    if [[ $color == always ]]; then
        printf 'Color enabled. For file-list colors use ls --color=auto (ls is not changed).\n'
    fi
    return 0
}

function v6alias-demo-off {
    local name status=0
    if [[ $_V6ALIAS_DEMO_ACTIVE != 1 ]]; then
        printf 'v6alias DEMO is already off.\n'
        return 0
    fi
    for name in "${_V6ALIAS_DEMO_NAMES[@]}"; do
        if [[ $(declare -f -- "$name") == "${_V6ALIAS_DEMO_FUNCTIONS[$name]}" ]]; then
            unset -f -- "$name"
        else
            printf 'Preserving changed/missing demo function: %s\n' "$name" >&2
            status=1
        fi
    done
    if [[ $_V6ALIAS_DEMO_PS1_SET == x ]]; then
        PS1=$_V6ALIAS_DEMO_PS1
    else
        unset PS1
    fi
    _V6ALIAS_DEMO_ACTIVE=0
    _V6ALIAS_DEMO_FUNCTIONS=()
    _V6ALIAS_DEMO_NATIVE=()
    unset _V6ALIAS_DEMO_BINARY _V6ALIAS_DEMO_CONFIG _V6ALIAS_DEMO_COLOR
    unset _V6ALIAS_DEMO_PS1 _V6ALIAS_DEMO_PS1_SET
    printf 'v6alias DEMO off; normal commands and original prompt restored (changed functions preserved).\n'
    return "$status"
}

export -n -f _v6alias_demo_absolute _v6alias_demo_network _v6alias_demo_native v6alias-demo-on v6alias-demo-off
_V6ALIAS_DEMO_LOADED=1
printf 'Loaded session helpers. Run v6alias-demo-on [--color] [BINARY [CONFIG]]; undo with v6alias-demo-off.\n'
