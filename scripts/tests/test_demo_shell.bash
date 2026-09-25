#!/usr/bin/env bash
# Offline: only mock executables run; unique scratch files stay beside this test.
# Run: bash scripts/tests/test_demo_shell.bash
set -euo pipefail
TEST_DIR=$(builtin cd -- "${BASH_SOURCE[0]%/*}" && builtin pwd -P)
SCRIPT=${TEST_DIR%/*}/demo-shell.bash
BASH_BIN=$BASH
SCRATCH=$TEST_DIR/.demo-shell-test.$BASHPID.$RANDOM.$RANDOM
(umask 077; mkdir -- "$SCRATCH")
trap 'rm -rf -- "$SCRATCH"' EXIT
TOOLS=$SCRATCH/tools\ with\ spaces
NATIVES=$SCRATCH/native\ tools
mkdir -- "$TOOLS" "$NATIVES"
export LOG=$SCRATCH/arguments CALLS=$SCRATCH/calls NATIVE_LOG=$SCRATCH/native
cat > "$TOOLS/v6alias" <<'MOCK'
#!/usr/bin/env bash
printf '%s\0' "$@" > "$LOG"
printf x >> "$CALLS"
if [[ ${MOCK_NATIVE:-0} == 1 ]]; then command ping -6 ::1; fi
exit "${MOCK_STATUS:-0}"
MOCK
cat > "$NATIVES/ping" <<'MOCK'
#!/usr/bin/env bash
printf '%s\0' "$0" "$@" > "$NATIVE_LOG"
exit "${NATIVE_STATUS:-0}"
MOCK
chmod +x "$TOOLS/v6alias" "$NATIVES/ping"
for name in traceroute tracert ssh ifconfig; do cp "$NATIVES/ping" "$NATIVES/$name"; done
printf 'profiles: {}\n' > "$TOOLS/v6alias.yaml"
cp "$TOOLS/v6alias.yaml" "$TOOLS/other config.yaml"
export PATH=$NATIVES:$PATH
ORIGINAL_PATH=$PATH
ORIGINAL_TERM=${TERM-unset}
BINARY=$TOOLS/v6alias
CONFIG=$TOOLS/v6alias.yaml

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
equal() { [[ $1 == "$2" ]] || fail "expected <$2>, got <$1>"; }
expect_status() {
    local expected=$1 status=0
    shift
    "$@" >/dev/null 2>&1 || status=$?
    equal "$status" "$expected"
}
args_in() {
    local file=$1 item
    shift
    local -a actual=()
    while IFS= read -r -d '' item; do actual+=("$item"); done < "$file"
    equal "${#actual[@]}" "$#"
    local i=0
    for item in "$@"; do equal "${actual[$i]}" "$item"; i=$((i + 1)); done
}
args() { args_in "$LOG" --config "$CONFIG" --color "${COLOR:-auto}" "$@"; }
load() { source "$SCRIPT" >/dev/null; }
enable() { v6alias-demo-on "$BINARY" "$CONFIG" >/dev/null; }
no_wrappers() {
    local name
    for name in ping trace traceroute tracert ssh ifconfig native-ping native-trace native-ssh native-ifconfig; do
        if declare -F -- "$name" >/dev/null; then fail "unexpected function: $name"; fi
    done
}

test_source_and_repeat() {
    expect_status 2 "$BASH_BIN" "$SCRIPT"
    load
    no_wrappers
    local definition
    definition=$(declare -f v6alias-demo-on)
    load
    equal "$(declare -f v6alias-demo-on)" "$definition"
    v6alias-demo-on --help >/dev/null
    no_wrappers
    enable
    definition=$(declare -f ping)
    load
    enable
    equal "$(declare -f ping)" "$definition"
    expect_status 2 v6alias-demo-on --color "$BINARY" "$CONFIG"
    expect_status 2 v6alias-demo-on "$BINARY" "$TOOLS/other config.yaml"
    equal "$(declare -f ping)" "$definition"
    equal "$PATH" "$ORIGINAL_PATH"
    equal "${TERM-unset}" "$ORIGINAL_TERM"
    "$BASH_BIN" -c 'for name in ping trace traceroute tracert ssh ifconfig native-ping native-trace native-ssh native-ifconfig v6alias-demo-on v6alias-demo-off; do
        if declare -F -- "$name" >/dev/null; then exit 1; fi
    done' || fail 'functions exported into child shell'
    v6alias-demo-off >/dev/null
    no_wrappers
    v6alias-demo-off >/dev/null
    enable
    v6alias-demo-off >/dev/null
}
test_forwarding() {
    load; enable
    ping corp:42 -c 3
    args ping corp:42 -- -c 3
    ssh corp:42 -l 'scout user' -o 'ProxyCommand=echo $(do-not-run)' ''
    args ssh corp:42 -- -l 'scout user' -o 'ProxyCommand=echo $(do-not-run)' ''
    local name
    for name in trace traceroute tracert; do
        "$name" corp:23.42 -m 3
        args trace corp:23.42 -- -m 3
    done
    ping corp:42 -c 3 --dry-run -- --dry-run -- '-x y'
    args ping corp:42 --dry-run -- -c 3 --dry-run -- '-x y'
    ping corp:42 --dry-run
    args ping corp:42 --dry-run --
    ping
    args ping --help
    ifconfig --raw --json --interface 'eth 0'
    args interfaces --raw --json --interface 'eth 0'
    ifconfig down
    args interfaces down
    export MOCK_STATUS=17
    expect_status 17 ping corp:42
    expect_status 17 ssh corp:42
    expect_status 17 trace corp:42
    expect_status 17 ifconfig --json
}
test_invalid_aliases() {
    load; enable
    : > "$CALLS"
    local value
    for value in '' localhost ::1 1.2.3.4 -c Corp:42 corp_name:42 corp: corp:0 \
        corp:01 corp:07.15 corp:65536 corp:65536.1 corp:1.2.3 \
        'corp:42;echo bad' 'corp:$(echo bad)' corp:999999999999999999999; do
        expect_status 2 ping "$value"
        expect_status 2 ssh "$value"
        expect_status 2 trace "$value"
    done
    [[ ! -s $CALLS ]] || fail 'invalid aliases invoked binary'
    ping corp:65535.65535
    args ping corp:65535.65535 --
    ping corp:0.1
    args ping corp:0.1 --
}
test_conflicts() {
    local name kind before
    for name in ping trace traceroute tracert ssh ifconfig native-ping native-trace native-ssh native-ifconfig; do
        for kind in alias function; do
            (
                if [[ $kind == alias ]]; then
                    alias "$name=printf untouched"
                    shopt -s expand_aliases
                else
                    # Fixed template, not eval or executable user input.
                    source /dev/stdin <<< "function $name { printf untouched; }"
                fi
                before=$(declare -f -- "$name" || :)
                load
                : > "$CALLS"
                expect_status 2 v6alias-demo-on "$BINARY" "$CONFIG"
                equal "$_V6ALIAS_DEMO_ACTIVE" 0
                [[ ! -s $CALLS ]] || fail 'conflict invoked binary'
                if [[ $kind == alias ]]; then
                    equal "$(alias "$name")" "alias $name='printf untouched'"
                    unalias "$name"
                else
                    equal "$(declare -f -- "$name")" "$before"
                    equal "$("$name")" untouched
                    unset -f "$name"
                fi
                no_wrappers
            )
        done
    done
}
test_paths_and_validation() {
    load
    expect_status 2 v6alias-demo-on "$TOOLS/missing" "$CONFIG"
    expect_status 2 v6alias-demo-on "$BINARY" "$TOOLS/missing"
    expect_status 2 v6alias-demo-on "$BINARY" "$CONFIG" extra
    expect_status 2 v6alias-demo-on --bogus
    no_wrappers
    builtin cd -- "$SCRATCH"
    export CDPATH=$SCRATCH
    v6alias-demo-on 'tools with spaces/v6alias' >/dev/null
    unset CDPATH
    builtin cd -- "$TEST_DIR"
    ping corp:42
    args ping corp:42 --
    v6alias-demo-off >/dev/null
    # Default discovery is exercised on a copy, without touching real binaries.
    mkdir -p "$SCRATCH/tree/scripts" "$SCRATCH/tree/dist/linux-x64"
    cp "$SCRIPT" "$SCRATCH/tree/scripts/demo-shell.bash"
    cp "$BINARY" "$CONFIG" "$SCRATCH/tree/dist/linux-x64/"
    "$BASH_BIN" -c 'source "$1" >/dev/null; v6alias-demo-on >/dev/null; ping corp:42' \
        bash "$SCRATCH/tree/scripts/demo-shell.bash"
    args_in "$LOG" --config "$SCRATCH/tree/dist/linux-x64/v6alias.yaml" --color auto ping corp:42 --
    cp "$BINARY" "$CONFIG" "$SCRATCH/tree/scripts/"
    "$BASH_BIN" -c 'source "$1" >/dev/null; v6alias-demo-on >/dev/null; ping corp:42' \
        bash "$SCRATCH/tree/scripts/demo-shell.bash"
    args_in "$LOG" --config "$SCRATCH/tree/scripts/v6alias.yaml" --color auto ping corp:42 --
}
test_prompt_and_color() {
    load
    export NO_COLOR=1
    alias ls='printf existing-ls'
    local original='\u@\h:\w\$ literal prompt '
    PS1=$original
    enable
    equal "$PS1" "$original"
    ping corp:42
    args ping corp:42 --
    v6alias-demo-off >/dev/null
    v6alias-demo-on --color "$BINARY" "$CONFIG" >/dev/null
    equal "$PS1" '\[\e[1;36m\]\u@\h\[\e[0m\]:\w\$ '
    [[ $PS1 != *'[DEMO]'* ]] || fail 'unexpected DEMO tag'
    local COLOR=always
    ifconfig --json
    args interfaces --json
    v6alias-demo-off >/dev/null
    equal "$PS1" "$original"
    equal "$NO_COLOR" 1
    unset PS1
    v6alias-demo-on --color "$BINARY" "$CONFIG" >/dev/null
    equal "$PS1" '\[\e[1;36m\]\u@\h\[\e[0m\]:\w\$ '
    v6alias-demo-off >/dev/null
    [[ ! ${PS1+x} ]] || fail 'unset PS1 not restored'
    PS1=
    v6alias-demo-on --color "$BINARY" "$CONFIG" >/dev/null
    v6alias-demo-off >/dev/null
    equal "${PS1+x}:$PS1" x:
    equal "$PATH" "$ORIGINAL_PATH"
    equal "${TERM-unset}" "$ORIGINAL_TERM"
    equal "$(alias ls)" "alias ls='printf existing-ls'"
}
test_native_and_no_recursion() {
    load; enable
    native-ping --help '-x y'
    args_in "$NATIVE_LOG" "$NATIVES/ping" --help '-x y'
    native-ssh -l 'scout user' ::1
    args_in "$NATIVE_LOG" "$NATIVES/ssh" -l 'scout user' ::1
    native-trace --help
    args_in "$NATIVE_LOG" "$NATIVES/traceroute" --help
    native-ifconfig --help
    args_in "$NATIVE_LOG" "$NATIVES/ifconfig" --help
    export MOCK_NATIVE=1
    : > "$CALLS"
    ping corp:42
    equal "$(< "$CALLS")" x
    args_in "$NATIVE_LOG" "$NATIVES/ping" -6 ::1
    export NATIVE_STATUS=17
    expect_status 17 native-ping ::1
    # Missing native executables produce explicit errors, without CLI fallback.
    v6alias-demo-off >/dev/null
    PATH=$TOOLS
    enable
    expect_status 127 native-ifconfig
    expect_status 127 native-trace
    PATH=$ORIGINAL_PATH
    v6alias-demo-off >/dev/null
    # A tracert-only PATH uses that executable as the native trace escape.
    mkdir "$SCRATCH/tracert-only"
    cp "$NATIVES/tracert" "$SCRATCH/tracert-only/tracert"
    PATH=$SCRATCH/tracert-only
    enable
    PATH=$ORIGINAL_PATH
    export NATIVE_STATUS=0
    native-trace --help
    args_in "$NATIVE_LOG" "$SCRATCH/tracert-only/tracert" --help
}
test_allexport() {
    set -a
    load; enable
    "$BASH_BIN" -c '[[ $(type -t ping) != function ]] && ! declare -F v6alias-demo-on >/dev/null' \
        || fail 'allexport leaked demo functions'
    v6alias-demo-off >/dev/null
    set +a
}
test_preserve_replacements() {
    load; PS1=original; enable
    function ping { printf replacement; }
    expect_status 2 v6alias-demo-on "$BINARY" "$CONFIG"
    expect_status 1 v6alias-demo-off
    equal "$(ping)" replacement
    equal "$PS1" original
    unset -f ping
    no_wrappers
}

for test in test_source_and_repeat test_forwarding test_invalid_aliases test_conflicts \
    test_paths_and_validation test_prompt_and_color test_native_and_no_recursion test_allexport test_preserve_replacements; do
    ( "$test" )
    printf 'PASS %s\n' "$test"
done
printf 'All demo-shell tests passed (offline).\n'
