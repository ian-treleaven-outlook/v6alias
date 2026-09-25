#!/usr/bin/env bash
# Run with: bash ~/v6alias/record-demo.bash
# Each keypress clears the console, visibly types a command, then executes it.
# This uses the existing isolated demo; it does not change network settings.
# Waiting is intentionally silent. Enter/Space advances; q quits between steps.

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
    printf 'Run this script with bash, rather than source.\n' >&2
    return 2
fi
if [[ ! -t 0 || ! -t 1 ]]; then
    printf 'Run this script directly in your interactive guest console.\n' >&2
    exit 2
fi

# Load the session-only ifconfig/ping/ssh shortcuts and the prepared SSH trust.
source "$HOME/v6alias/live-demo.bash" >/dev/null || exit 1
cd "$HOME/v6alias" || exit 1
demo_user=$(id -un) || exit 1
demo_host=$(hostname -s) || exit 1
trap 'printf "\nRecording sequence interrupted.\n"; exit 130' INT

next_command() {
    local key='' display="$*" i status
    IFS= read -r -s -n 1 key || return 1
    if [[ $key == q || $key == Q ]]; then
        printf '\n'
        exit 0
    fi

    # Clear before showing the prompt; slow typing is only a visual effect.
    clear || return
    printf '\033[1;36m%s@%s\033[0m:~/v6alias$ ' "$demo_user" "$demo_host"
    for ((i = 0; i < ${#display}; i++)); do
        printf '%s' "${display:i:1}"
        sleep 0.035
    done
    printf '\n'

    # Execute the argument array directly, never eval the displayed string.
    "$@"
    status=$?
    if ((status != 0)); then
        printf '\nCommand failed (exit %s). Stopping so you can investigate.\n' "$status" >&2
    fi
    return "$status"
}

next_command ifconfig || exit $?
next_command cat /opt/v6alias-live-demo/v6alias.local.yaml || exit $?
# Bound both packet count and total duration so a failed ping cannot hang.
next_command ping corp:43 -c 3 -W 2 -w 10 || exit $?
next_command ping lab:7.15 -c 3 -W 2 -w 10 || exit $?
next_command ssh corp:42 || exit $?
