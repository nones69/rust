# C sources

| Path | Status |
|------|--------|
| [`reference/`](reference/) | **Supported** host harness — `make test_harness` |
| [`kernel/`](kernel/), [`arch/`](arch/) | **Experimental** incomplete bare-metal stubs (`make kernel` needs `x86_64-elf-gcc` + nasm). Not the IntentOS prototype path. Prefer [`../iso-build/`](../iso-build/) for intentional ISO work. |

`test_harness.c` drives the reference capability table.
