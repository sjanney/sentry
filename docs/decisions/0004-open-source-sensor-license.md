# Open-source sensor license

Status: accepted

## Scope

This decision covers the Sentry sensor repository: kernel programs, daemon,
policy library, CLI, test harnesses, and documentation authored for Sentry. It
does not license third-party dependencies or a future hosted policy/control
plane.

## Viable options

| Option | Effect | Fit for Sentry |
| --- | --- | --- |
| Apache-2.0 | Permissive reuse plus an express patent license and termination condition | Recommended for an infrastructure-security sensor that enterprises may inspect, modify, and embed. |
| MIT | Short permissive license with fewer explicit protections | Simple, but provides no express patent grant. |
| AGPL-3.0-or-later | Strong network copyleft | Encourages source sharing but raises adoption friction for the platform teams this sensor targets. |

## Dependency compatibility

The current Aya candidate is dual MIT or Apache-2.0, which is compatible with
either permissive option. The libbpf-rs candidate is a Rust wrapper around
libbpf and requires a separate dependency and distribution review if selected;
choosing a permissive Sentry license does not remove third-party notice or
linking obligations.

The BPF program `LICENSE` sections are kernel-loader declarations, not the
repository copyright license. The probe programs retain `GPL` there so their
use of GPL-only BPF helpers remains valid; their source files can still carry
the repository license once selected.

## Recommendation

Apache-2.0 is selected for the sensor. It matches Aya’s permissive licensing,
is familiar to enterprise adopters, includes an express patent grant, and keeps
the future commercial control plane outside this repository without restricting
users who run the sensor themselves.

## Applied actions

1. Added the Apache-2.0 top-level license text. New Sentry-authored source
   files use the `Apache-2.0` SPDX identifier unless a more specific file-level
   notice is required.
2. Replace provisional SPDX identifiers in existing Sentry-authored test sources with
   the selected repository license where appropriate; retain BPF loader
   declarations separately.
3. Add third-party notices based on the selected eBPF toolchain’s actual
   dependency graph.

## Sources

- Apache License 2.0: <https://www.apache.org/licenses/LICENSE-2.0>
- MIT License (OSI): <https://opensource.org/license/mit>
- GNU AGPLv3: <https://www.gnu.org/licenses/agpl-3.0.en.html>
