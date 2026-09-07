# YSD Node Agent

The agent turns a machine you own into a YSD Compute Node. Control-plane traffic
is outbound HTTPS. Agent `0.6.0` also uses a local named pipe on Windows or a
protected Unix-domain socket on Linux/macOS solely to prevent a second Agent
from owning the same node identity; it is not a network listener.

Phase 5 executes diagnostics, reviewed `ai.inference` and `ai.model.acquire`
jobs, and narrow Minecraft Java Game Server actions. AI speaks only to Ollama on
`127.0.0.1:11434` or a llama.cpp server on `127.0.0.1:8080`. Game Server
downloads use only reviewed Mojang HTTPS hosts and launch `java` with fixed
arguments and `shell=false`. No job can choose an executable, command, script,
filesystem path, JVM argument, provider, tunnel, or network destination.

## Pair

Create a one-time ticket on the Nodes page, download the published Agent, verify
the displayed SHA-256, and run:

```powershell
$env:YSD_NODE_URL = 'https://ysd-zero-cloud.ysd-zero-cloud.workers.dev'
node ysd-node-agent-0.6.0.mjs pair --url $env:YSD_NODE_URL
```

Type the one-time code at the prompt. The bearer credential is AES-256-GCM
encrypted in the per-user Agent home with a generated local key. Neither is
sent back to YSD after pairing.

## Run

```powershell
$env:YSD_NODE_URL = 'https://ysd-zero-cloud.ysd-zero-cloud.workers.dev'
node ysd-node-agent-0.6.0.mjs run --url $env:YSD_NODE_URL
```

## Start automatically when you sign in

```powershell
node ysd-node-agent-0.6.0.mjs autostart enable --url $env:YSD_NODE_URL
node ysd-node-agent-0.6.0.mjs autostart status
node ysd-node-agent-0.6.0.mjs autostart repair --url $env:YSD_NODE_URL
node ysd-node-agent-0.6.0.mjs autostart disable
```

Windows uses a current-user Task Scheduler logon task, Linux uses a systemd
user unit without linger, and macOS uses a per-user LaunchAgent. No password or
node secret is stored in the registration. This starts after user sign-in, not
before login. If the credential depends on an explicit `YSD_NODE_AGENT_KEY`
environment override, enablement refuses with `credential_key_unavailable`
rather than copying the secret into the background configuration.

The agent automatically detects a loopback Ollama or llama.cpp API and its
cached models. It never installs either runtime. Model acquisition requires an
explicit approval in AI Center, uses an exact reviewed Ollama library name,
checks the disk reserve and reported digest, and removes only that partial model
if verification fails.

Set `YSD_NODE_GPU` to a GPU model name and `YSD_NODE_GPU_VRAM_BYTES` to its VRAM
in bytes when you want the scheduler to enforce a GPU model requirement. Set
`YSD_NODE_DOCKER=true` only when you want to advertise Docker availability; it
is not used by the Game Server runtime.

Minecraft Java requires a supported local Java runtime. Accept the Minecraft
EULA explicitly in the Game Servers create form; the agent never accepts it on
your behalf. Each server is stored below `.ysd-game-servers/<workspace>/<server>`
beside the encrypted agent credential. Worlds, complete logs, and checksum-
verified backups never leave that machine. The agent opens no port, configures
no UPnP rule, and creates no tunnel; any network access is a separate manual
decision by the machine owner.
