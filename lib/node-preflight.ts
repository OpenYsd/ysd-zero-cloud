import { APP_RUNTIME_LIMITS } from './app-runtime.ts';
import { meetsMinimumNodeVersion, MINIMUM_NODE_VERSION } from './agent-release.ts';
import {
  agentVersionSupported,
  CURRENT_AGENT_VERSION,
  deriveNodeStatus,
  MINIMUM_AGENT_VERSION,
  NODE_PROTOCOL_VERSION,
  type NodeCapabilities,
  type NodeStatus,
} from './nodes.ts';

/**
 * Whether a Compute Node can actually take a deployment, decided from data the
 * control plane already holds.
 *
 * Two things this deliberately is not.
 *
 * It is not a remote command. Nothing here runs on the node, and nothing here
 * executes repository code -- it reads the capability report the agent already
 * sends on every heartbeat and the row the pairing wrote. A "preflight" that
 * shelled out to the node would be a far more attractive target than the
 * problem it solves.
 *
 * It is not decoration. `lib/server/deployments.ts` re-evaluates the blocking
 * subset at queue time, so a browser cannot pass a "preflight ok" flag and get
 * a job. This module produces the explanation; the server keeps the authority.
 *
 * The capability report is treated as untrusted input throughout: it is parsed
 * and range-checked before it reaches here, every number is compared rather
 * than displayed, and no string from the node is ever echoed into remediation
 * text. Remediation is chosen from the fixed table below.
 */

export const PREFLIGHT_VERSION = 1;

export type PreflightStatus = 'passed' | 'blocked' | 'unknown';

export type PreflightCheckCode =
  | 'node-workspace'
  | 'node-heartbeat'
  | 'agent-version'
  | 'agent-protocol'
  | 'app-runtime-contract'
  | 'app-runtime-node'
  | 'app-runtime-capacity'
  | 'node-memory'
  | 'node-disk';

export type PreflightCheck = {
  code: PreflightCheckCode;
  status: PreflightStatus;
  title: string;
  remediation: string;
};

export type PreflightReport = {
  version: typeof PREFLIGHT_VERSION;
  verdict: 'ready' | 'blocked';
  checks: PreflightCheck[];
};

/** Where a node sits relative to the agent contract this control plane speaks. */
export type CompatibilityVerdict =
  | 'compatible'
  | 'upgrade_required'
  | 'protocol_mismatch'
  | 'unknown';

export type CompatibilityInput = {
  agentVersion: string | null;
  protocolVersion: number | null;
};

export function evaluateCompatibility(input: CompatibilityInput): CompatibilityVerdict {
  if (!input.agentVersion || input.protocolVersion === null) return 'unknown';
  if (!agentVersionSupported(input.agentVersion)) return 'upgrade_required';
  if (input.protocolVersion !== NODE_PROTOCOL_VERSION) return 'protocol_mismatch';
  return 'compatible';
}

/**
 * One line for the Nodes list. `online` alone is not deploy-ready and the UI
 * must never imply that it is, which is the whole reason this is a separate
 * word from the heartbeat status.
 */
export function compatibilityLabel(
  status: NodeStatus,
  verdict: CompatibilityVerdict,
): string {
  if (status === 'revoked') return 'Revoked';
  if (status === 'offline') return 'Offline';
  if (status === 'stale') return 'Stale';
  if (verdict === 'upgrade_required') return 'Online — upgrade required';
  if (verdict === 'protocol_mismatch') return 'Online — incompatible protocol';
  if (verdict === 'unknown') return 'Online — capabilities unknown';
  return 'Online — ready';
}

export type PreflightInput = {
  /** True when the node row was read from the caller's own workspace. */
  belongsToWorkspace: boolean;
  status: NodeStatus;
  agentVersion: string | null;
  protocolVersion: number | null;
  capabilities: NodeCapabilities | null;
  /** Memory the pending deployment asks for, when one is being planned. */
  requestedMemoryMb?: number;
  /** Disk the pending deployment asks for, when one is being planned. */
  requestedDiskBytes?: number;
};

function check(
  code: PreflightCheckCode,
  status: PreflightStatus,
  title: string,
  remediation: string,
): PreflightCheck {
  return { code, status, title, remediation };
}

/**
 * The remediation strings live here, not at the call site, so every one of them
 * is reviewable in a single place and none can be assembled from node input.
 */
export function evaluatePreflight(input: PreflightInput): PreflightReport {
  const checks: PreflightCheck[] = [];

  checks.push(
    input.belongsToWorkspace
      ? check('node-workspace', 'passed', 'Node belongs to this workspace', 'No action needed.')
      : check(
          'node-workspace',
          'blocked',
          'Node is not in this workspace',
          'Select a Compute Node paired to this workspace.',
        ),
  );

  if (input.status === 'online') {
    checks.push(check('node-heartbeat', 'passed', 'Heartbeat is current', 'No action needed.'));
  } else {
    checks.push(
      check(
        'node-heartbeat',
        'blocked',
        input.status === 'revoked' ? 'Node was revoked' : 'Node is not reporting',
        input.status === 'revoked'
          ? 'Pair a new Compute Node. A revoked credential cannot be restored.'
          : 'Start the agent on the node with the run command, then wait for the next heartbeat.',
      ),
    );
  }

  const compatibility = evaluateCompatibility({
    agentVersion: input.agentVersion,
    protocolVersion: input.protocolVersion,
  });
  if (compatibility === 'compatible') {
    checks.push(check('agent-version', 'passed', 'Agent version is supported', 'No action needed.'));
    checks.push(check('agent-protocol', 'passed', 'Protocol matches', 'No action needed.'));
  } else if (compatibility === 'upgrade_required') {
    checks.push(
      check(
        'agent-version',
        'blocked',
        'Agent is older than the supported minimum',
        `Download agent ${CURRENT_AGENT_VERSION} and pair again. Minimum supported is ${MINIMUM_AGENT_VERSION}.`,
      ),
    );
  } else if (compatibility === 'protocol_mismatch') {
    checks.push(
      check(
        'agent-protocol',
        'blocked',
        'Agent speaks a different protocol',
        `Download agent ${CURRENT_AGENT_VERSION}, which speaks protocol ${NODE_PROTOCOL_VERSION}.`,
      ),
    );
  } else {
    checks.push(
      check(
        'agent-version',
        'unknown',
        'Agent has not reported a version yet',
        'Wait for the next heartbeat, then check again.',
      ),
    );
  }

  const capabilities = input.capabilities;
  if (!capabilities) {
    checks.push(
      check(
        'app-runtime-contract',
        'unknown',
        'Capabilities have not been reported',
        'Wait for the next heartbeat, then check again.',
      ),
    );
    return finish(checks);
  }

  const appRuntime = capabilities.appRuntime;
  if (!capabilities.contracts.appRuntime || !appRuntime?.available) {
    checks.push(
      check(
        'app-runtime-contract',
        'blocked',
        'App Runtime is not available on this node',
        'Install a supported Node.js runtime on the node and restart the agent so it advertises the App Runtime contract.',
      ),
    );
  } else {
    checks.push(
      check('app-runtime-contract', 'passed', 'App Runtime contract advertised', 'No action needed.'),
    );

    checks.push(
      meetsMinimumNodeVersion(appRuntime.nodeVersion)
        ? check('app-runtime-node', 'passed', 'Node.js runtime is supported', 'No action needed.')
        : check(
            'app-runtime-node',
            'blocked',
            'Node.js on the node is too old',
            `Install Node.js ${MINIMUM_NODE_VERSION} or newer on the node and restart the agent.`,
          ),
    );

    checks.push(
      appRuntime.activeDeployments < appRuntime.maxDeployments
        ? check('app-runtime-capacity', 'passed', 'Deployment capacity available', 'No action needed.')
        : check(
            'app-runtime-capacity',
            'blocked',
            'Node reached its deployment ceiling',
            'Stop or delete an existing deployment on this node, then check again.',
          ),
    );
  }

  // Resource headroom. Both numbers come from the node's own report, so they
  // are compared against the same reserves `planDeployment` enforces rather
  // than being shown as trustworthy free-space figures.
  const memoryNeeded =
    (input.requestedMemoryMb ?? APP_RUNTIME_LIMITS.memoryMinimumMb) * 1024 ** 2
    + APP_RUNTIME_LIMITS.memoryReserveBytes;
  checks.push(
    capabilities.memory.freeBytes >= memoryNeeded
      ? check('node-memory', 'passed', 'Enough free memory reported', 'No action needed.')
      : check(
          'node-memory',
          'blocked',
          'Not enough free memory reported',
          'Close other workloads on the node, then check again.',
        ),
  );

  const diskNeeded =
    (input.requestedDiskBytes ?? APP_RUNTIME_LIMITS.diskMinimumBytes)
    + APP_RUNTIME_LIMITS.diskReserveBytes;
  checks.push(
    capabilities.disk.freeBytes >= diskNeeded
      ? check('node-disk', 'passed', 'Enough free disk reported', 'No action needed.')
      : check(
          'node-disk',
          'blocked',
          'Not enough free disk reported',
          'Free space on the node, then check again.',
        ),
  );

  return finish(checks);
}

function finish(checks: PreflightCheck[]): PreflightReport {
  // `unknown` does not block. It means the node has not spoken yet, which is a
  // "wait", not a refusal -- and the server re-checks the blocking subset at
  // queue time regardless, so a wrong guess here cannot let a job through.
  const blocked = checks.some((entry) => entry.status === 'blocked');
  return {
    version: PREFLIGHT_VERSION,
    verdict: blocked ? 'blocked' : 'ready',
    checks,
  };
}

/** The check codes that failed, for evidence. Codes only -- never free text. */
export function failedCheckCodes(report: PreflightReport): PreflightCheckCode[] {
  return report.checks.filter((entry) => entry.status === 'blocked').map((entry) => entry.code);
}

/**
 * The blocking subset the deployment path enforces.
 *
 * Kept separate from the full report on purpose: the report exists to explain,
 * and this exists to refuse. A check that is only advisory must never be able
 * to creep into the refusal path by being added to the report.
 */
export function deploymentBlockers(input: PreflightInput): PreflightCheckCode[] {
  const report = evaluatePreflight(input);
  const blocking = new Set<PreflightCheckCode>([
    'node-workspace',
    'node-heartbeat',
    'agent-version',
    'agent-protocol',
    'app-runtime-contract',
    'app-runtime-node',
    'app-runtime-capacity',
  ]);
  return failedCheckCodes(report).filter((code) => blocking.has(code));
}

export { deriveNodeStatus };
