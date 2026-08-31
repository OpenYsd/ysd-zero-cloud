import handler from 'vinext/server/fetch-handler';

import { runWorkflowEngineTick } from '@/lib/server/workflows';

/**
 * The existing vinext Worker with one free-plan Cron Trigger entrypoint.
 * The trigger only advances the D1 state machine; no Queue, Durable Object,
 * Cloudflare Workflow, outbound provider, or billable binding is involved.
 */
export default {
  fetch(request, env, context) {
    return handler.fetch(request, env, context);
  },
  scheduled(controller, _env, context) {
    context.waitUntil(
      runWorkflowEngineTick(controller.scheduledTime)
        .then((result) => {
          console.log(JSON.stringify({
            message: 'workflow tick complete',
            cron: controller.cron,
            ...result,
          }));
        })
        .catch((error: unknown) => {
          console.error(JSON.stringify({
            message: 'workflow tick failed',
            error: error instanceof Error ? error.message : String(error),
          }));
          throw error;
        }),
    );
  },
} satisfies ExportedHandler<Cloudflare.Env>;
