# CRASS OS ↔ Host IntentKernel Bridge

The `ikrl-bridge` daemon translates CRASS OS IPC messages into the
length-prefixed JSON protocol used by the host daemon stack.

## Ports

| Service | Default |
|---------|---------|
| `intentd` | `tcp://127.0.0.1:9100` |
| `capd` | `tcp://127.0.0.1:9101` |
| `leasebroker` | `tcp://127.0.0.1:9102` |
| `eventscope` | `tcp://127.0.0.1:9103` |
| `ikrl-bridge` | `tcp://127.0.0.1:9300` |

## CRASS channel map

| CRASS slot | Host daemon |
|------------|-------------|
| 1 (`CAPD_CHANNEL`) | `capd` |
| 2 (`INTENTD_CHANNEL`) | `intentd` |
| 3 (`LEASEBROKER_CHANNEL`) | `leasebroker` |
| 4 (`EVENTSCOPE_CHANNEL`) | `eventscope` |
| 12 (`IPDESCRAMBLER_CHANNEL`) | `intentd` (IP policy via `GetPolicy`) |

## Wire format

Send a JSON envelope to `ikrl-bridge`:

```json
{
  "channel_slot": 2,
  "msg_type": 1,
  "data": [115, 101, 110, 100, 32, 110, 101, 116, 119, 111, 114, 107, 32, 56, 46, 56, 46, 56, 46, 56]
}
```

`data` is the raw CRASS IPC payload (`"send network 8.8.8.8"` in the example).

The bridge returns:

```json
{"status": "Ok", "data": { ... host daemon response ... }}
```

## Boot with bridge

```powershell
.\rust\target\release\ikrl-init.exe --bin-dir .\rust\target\release --with-bridge
```

Or use the one-click launcher:

```powershell
.\scripts\launch-intentkernel.ps1
```

## QEMU side (CRASS OS)

Point CRASS user-space tooling at `127.0.0.1:9300` when running QEMU with
host port forwarding, or embed bridge calls in a future `netd` proxy daemon.