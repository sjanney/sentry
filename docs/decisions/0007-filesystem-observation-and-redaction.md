# Filesystem observation and credential redaction

Status: accepted

Filesystem events distinguish attempted, successful, and denied accesses. A
credential-class target is stored as its class only, never its pathname or
contents. The MVP classes are SSH keys, cloud credentials, `.env` files,
keyrings, and token caches.

Sentry tracks Linux device/inode identity after path resolution. This lets an
already-classified target remain classified through a symlink, rename, or
hardlink. A denied access without resolvable metadata remains classified from
its requested path but has no identity. Namespace-aware kernel identity and
race-free path capture remain kernel integration work; generated policy must
not overclaim identity coverage before that evidence exists.
