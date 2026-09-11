# Failure and policy lifecycle contract

In enforce mode, daemon death, event loss, audit-write failure, disk full, map
exhaustion, and shutdown place Sentry in `RefusingNewRuns`. This visible state
prevents new policy activation or launches rather than silently failing open.
The current process state is not proof of continued enforcement after a daemon
failure, so operators must terminate or isolate it through the launch
supervisor before resuming service.

In dry-run mode the same faults produce `AuditIncomplete`, preserving a visible
record that evidence is incomplete. Policy activation keeps one prior identity;
a healthy runtime can roll back to it. Refusal blocks reload and rollback until
the supervising system restarts a healthy runtime. The state-machine tests
cover every declared fault plus reload/rollback, but kernel-map and real disk
exhaustion integration tests remain release-matrix work.
