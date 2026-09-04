import handler from 'vinext/server/fetch-handler';

import { runDataLifecycleMaintenance } from '@/lib/server/retention';
import { runShieldPostureSweep } from '@/lib/server/shield-schedule';
import { runWorkflowEngineTick } from '@/lib/server/workflows';

/**
 * The existing vinext Worker with one free-plan Cron Trigger entrypoint.
 * The trigger only advances the D1 state machine; no Queue, Durable Object,
 * Cloudflare Workflow, outbound provider, or billable binding is involved.
 *
 * Phase 12 adds a maintenance phase to this same tick rather than a second
 * trigger. It runs after the workflow engine and is isolated from it: the
 * maintenance promise catches its own failures so a retention problem can
 * never stop workflow execution, and every stage inside it is row-capped.
 *
 * Phase 15 adds a third phase on the same principle. It is last because it is
 * the least urgent of the three, it is capped at
 * `POSTURE_LIMITS.workspacesPerTick` workspaces, and it swallows its own
 * failures so a Shield problem cannot take down either phase above it.
 */
export default {
  fetch(request, env, context) {
    return handler.fetch(request, env, context);
  },
  scheduled(controller, _env, context) {
    context.waitUntil(
      (async () => {
        try {
          const result = await runWorkflowEngineTick(controller.scheduledTime);
          console.log(JSON.stringify({
            message: 'workflow tick complete',
            cron: controller.cron,
            ...result,
          }));
        } catch (error: unknown) {
          console.error(JSON.stringify({
            message: 'workflow tick failed',
            error: error instanceof Error ? error.message : String(error),
          }));
          throw error;
        }

        // Phase 12 is a maintenance phase of the existing tick. Chaining it
        // here preserves the Phase 9 engine as the first responsibility and
        // avoids two independent scheduled tasks racing over shared D1 state.
        try {
          const result = await runDataLifecycleMaintenance(controller.scheduledTime);
          console.log(JSON.stringify({
            message: 'data lifecycle maintenance complete',
            cron: controller.cron,
            ...result,
          }));
        } catch {
          // Swallowed on purpose. Maintenance is best-effort housekeeping; the
          // next tick retries, and the workflow engine above must not be
          // failed by it.
          console.error(JSON.stringify({
            message: 'data lifecycle maintenance failed',
            error: 'maintenance-unavailable',
          }));
        }

        // Phase 15. Bounded by workspace count per tick, not by how many
        // workspaces exist, so this cannot grow into the tick budget as the
        // platform does.
        try {
          const result = await runShieldPostureSweep(controller.scheduledTime);
          console.log(JSON.stringify({
            message: 'shield posture sweep complete',
            cron: controller.cron,
            ...result,
          }));
        } catch {
          // Same reasoning as the phase above, and one step stronger: a scan
          // reads a workspace's whole schema, so its failure modes are the
          // broadest of the three and the least entitled to fail the tick.
          console.error(JSON.stringify({
            message: 'shield posture sweep failed',
            error: 'sweep-unavailable',
          }));
        }
      })(),
    );
  },
} satisfies ExportedHandler<Cloudflare.Env>;
