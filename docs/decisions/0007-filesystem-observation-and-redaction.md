# Filesystem observation and credential redaction

Status: accepted

Filesystem events distinguish attempted, successful, and denied accesses. A
credential-class target is stored as its class only, never its pathname or
contents. The MVP classes are SSH keys, cloud credentials, `.env` files,
keyrings, and token caches.

Sentry tracks Linux device/inode identity after path resolution. This lets an
already-classified target remain classified through a symlink, rename, or
hardlink.

The Linux observer preloads only device/inode-to-class entries into a bounded
BPF map. A `file_open` LSM hook matches the resolved inode, and raw syscall
entry/exit hooks emit separate attempted and final-result records. The 72-byte
record contains the event header, credential class, result or positive errno,
device, and inode. It has no pathname or content field. Paths are used only by
the supervisor while resolving configured identities before attachment; they
never enter a BPF map, ring buffer, normalized event, or capture output.

Native arm64 tests cover all five classes plus hardlink, symlink, rename, and
bind-mount access from a separate mount namespace. Those aliases resolve to the
same kernel file identity. The observer covers `open`, `openat`, and `openat2`
calls that reach `file_open`. A denial applied after this hook can be reported
from the syscall result. DAC and other failures that occur before `file_open`
are invisible, and successful `execve` opens do not return through the paired
syscall-exit path. Inherited descriptors, mmap of an existing descriptor, and
identity replacement after configuration are also outside this evidence.
Generated policy and attestations must keep those cases marked incomplete.
