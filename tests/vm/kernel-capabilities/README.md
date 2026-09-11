# Kernel capability preflight

Run from the repository root:

```sh
bash tests/vm/kernel-capabilities/probe-arm64-container.sh
```

The probe reports BTF, cgroup-v2, seccomp mode, and the active-LSM preflight
state from a privileged disposable Docker Linux container. It deliberately
does not call a preflight result proof of enforcement. It also proves a
minimal launch-time seccomp filter can deny `getppid` in its own disposable
process. It then loads a BPF LSM `file_open` program and verifies it denies a
single synthetic file only for its own disposable loader process. The loader
uses the Docker Linux VM's PID namespace because the BPF helper reports VM PIDs
rather than container PID-namespace values. The network attachment test in the
probe loads a cgroup `connect4` program and verifies it rejects a synthetic
loopback connection only for the same loader process. The broader CO-RE,
verifier-diagnostic, and x86_64 checks in the decision record remain required.
