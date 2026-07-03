#!/usr/bin/env bash
# Legacy alias — delegates to Appendix B bootstrap script.
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/bootstrap-host.sh" "$@"