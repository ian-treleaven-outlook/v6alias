# Source this file inside the prepared guest: source ~/v6alias/live-demo.bash
# The demo's addresses were staged manually. These functions never allocate an
# interface address or apply DHCP/DNS changes, and do not change PATH or TERM.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    printf 'Use: source ~/v6alias/live-demo.bash\n' >&2
    exit 2
fi

if [[ ! -x /opt/v6alias-live-demo/v6alias ||
      ! -r /opt/v6alias-live-demo/v6alias.local.yaml ]]; then
    printf 'The approved live-demo package is not installed in this guest.\n' >&2
    return 2
fi

source /opt/v6alias-live-demo/demo-shell.bash || return
v6alias-demo-on --color /opt/v6alias-live-demo/v6alias \
    /opt/v6alias-live-demo/v6alias.local.yaml || return

printf '\n\033[1;96mSINGLE-CONSOLE DEMO\033[0m: manually staged IPv6; no guest Internet.\n'
printf '  \033[1;92mcorp:10\033[0m = starting console (corp-10)\n'
printf '  \033[1;92mcorp:43\033[0m = ping destination (corp-43)\n'
printf '  \033[1;92mcorp:42\033[0m = key-only SSH destination (corp-42)\n'
printf '  \033[1;95mlab:7.15\033[0m = routed lab target (lab-7-15)\n'
printf '\nShow: ifconfig\nLocal ping: ping corp:43 -c 3\nRouted ping: ping lab:7.15 -c 3\nSSH: ssh corp:42 -l scout-user\n'
printf 'Inside SSH: hostname; then exit to return here.\n'
printf 'Undo shortcuts: v6alias-demo-off. Ctrl+] returns to the Windows menu.\n\n'
