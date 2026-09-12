# Egress enforcement evidence and limitations

The privileged arm64 probe attaches disposable cgroup `connect4` and `connect6`
programs. It verifies `EPERM` before completion for direct loopback IPv4 and
IPv6 TCP and UDP connects. The synthetic policy denies unknown direct-IP
destinations, so this is fail-closed evidence for new supported connects. It
also creates a TCP socket before policy activation and verifies that its later
`connect` is denied, showing that socket creation alone is not a bypass.

This probe does not bind DNS evidence, enforce per-domain or per-CIDR policy,
or prove rebinding and proxy attribution. A socket connected before activation,
an inherited connected descriptor, and traffic that does not issue a new
`connect` are unsupported by these hooks. The runtime must reject policies
claiming coverage of those paths until additional controls and adversarial
tests exist.
