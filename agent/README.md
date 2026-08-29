# YSD Node Agent

The agent turns a machine you own into a YSD Compute Node. It opens no port and
runs no listener: heartbeat, job polling, claims, and completion all travel as
outbound HTTPS requests to the existing Worker.

Phase 3 executes only `diagnostic.ping` and `diagnostic.snapshot`. The runtime
does not import `child_process`, does not evaluate code, and has no generic
shell handler. Docker, GPU, AI, and game-server values are capability contracts
for later phases, not execution access.

## Pair

Create a one-time ticket on the Nodes page. In PowerShell, from this repository:

```powershell
$env:YSD_NODE_URL = 'https://ysd-zero-cloud.ysd-zero-cloud.workers.dev'
$env:YSD_NODE_PAIRING_CODE = '<one-time code>'
$env:YSD_NODE_AGENT_KEY = '<a local passphrase with at least 16 characters>'
node --experimental-strip-types agent/cli.ts pair --url $env:YSD_NODE_URL
```

The bearer credential is AES-256-GCM encrypted in
`.ysd-node-agent.credentials`; the passphrase is never sent to YSD. Keep the
passphrase in your operating system's secret manager when running the agent as
a service.

## Run

```powershell
$env:YSD_NODE_URL = 'https://ysd-zero-cloud.ysd-zero-cloud.workers.dev'
$env:YSD_NODE_AGENT_KEY = '<the same local passphrase>'
node --experimental-strip-types agent/cli.ts run --url $env:YSD_NODE_URL
```

Set `YSD_NODE_GPU` to a GPU model name and `YSD_NODE_DOCKER=true` only when you
want to advertise those future capabilities. They do not enable either job
type in Phase 3.
