# Filesystem enforcement evidence and limitations

The privileged arm64 probe loads a disposable BPF LSM `file_open` program that
denies a configured synthetic inode with `EACCES`. It proves that a separate
workspace fixture remains readable and that direct, hard-link, and symlink
opens of the protected inode are denied. This is inode-based evidence, so the
alias cases exercise the same policy identity rather than a pathname match.

The current hook covers a new file open only. An inherited descriptor opened
before policy activation, `mmap` of an already-open descriptor, and read paths
that do not issue a new `file_open` are unsupported guarantees. The MVP must
reject any policy that claims comprehensive credential-read coverage until
additional hooks and adversarial runtime tests prove those paths. The probe is
an enforcement capability test, not an end-to-end Sentry policy activation.
