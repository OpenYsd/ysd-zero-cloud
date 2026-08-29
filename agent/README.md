# YSD Node Agent

The agent turns a machine you own into a YSD Compute Node. It opens no port and
runs no listener: heartbeat, job polling, claims, and completion all travel as
outbound HTTPS requests to the existing Worker.

Phase 4 executes diagnostics plus reviewed `ai.inference` and
`ai.model.acquire` jobs. It speaks only to Ollama on `127.0.0.1:11434` or a
llama.cpp server on `127.0.0.1:8080`. Job payloads cannot replace those origins,
select a path, provide a model URL, or execute a command. The runtime does not
import `child_process`, evaluate code, or expose a generic shell handler. Game
Server values remain contracts only and are never executed.

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

The agent automatically detects a loopback Ollama or llama.cpp API and its
cached models. It never installs either runtime. Model acquisition requires an
explicit approval in AI Center, uses an exact reviewed Ollama library name,
checks the disk reserve and reported digest, and removes only that partial model
if verification fails.

Set `YSD_NODE_GPU` to a GPU model name and `YSD_NODE_GPU_VRAM_BYTES` to its VRAM
in bytes when you want the scheduler to enforce a GPU model requirement. Set
`YSD_NODE_DOCKER=true` only to advertise the inactive Game Server capability;
it does not grant execution access.
