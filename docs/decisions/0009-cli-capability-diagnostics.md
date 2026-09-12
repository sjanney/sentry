# CLI capability diagnostics and attach limitations

Status: accepted

`sentry run -- <command>` and `sentry observe -- <command>` invoke arbitrary
commands and return the command's exit code. They do not claim enforcement
until the kernel observer is integrated. `sentry attach <pid>` returns a
best-effort Linux `/proc` snapshot with a stable process start identity and
explicit partial coverage. It neither attaches a live sensor nor upgrades to
complete coverage after a later exec.

`sentry capabilities` lists these limits. Non-Linux hosts return a typed
unsupported-host error instead of panicking or presenting an enforcement claim.
On Linux, a signal-terminated child causes the wrapper to raise that same
signal after it has reaped the child. This preserves the signal result for
supervisors as well as the ordinary exit-code path.
