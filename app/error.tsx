'use client';

import { useEffect } from 'react';
import { RotateCcw, TriangleAlert } from 'lucide-react';
import { Button } from '@/components/ui/button';

/**
 * Route-level error boundary.
 *
 * Before this existed, an exception thrown while rendering any authenticated
 * view took the whole document with it: the operator saw a blank or broken page
 * and the only way back was a manual reload. The shell is rendered by the root
 * layout, which sits above this boundary, so navigation and sign-out survive
 * while only the failed view is replaced.
 *
 * Nothing from the exception is shown. A message can carry a query fragment, a
 * row value, or a driver detail, none of which belong on screen. `digest` is
 * the identifier the framework also writes to the server log, so it is the one
 * safe thing to surface for correlating a report with a trace.
 */
export default function RouteError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Server-rendered failures are already logged by the runtime; this covers
    // the client half so a browser-only failure is not silent.
    console.error(
      JSON.stringify({ message: 'route render failed', digest: error.digest ?? null }),
    );
  }, [error]);

  return (
    <div className="grid min-h-[60vh] place-items-center p-6">
      <div className="cloud-card w-full max-w-md space-y-4 p-6 text-center">
        <span className="mx-auto grid size-10 place-items-center rounded-full border border-amber-300/20 bg-amber-300/10 text-amber-300/80">
          <TriangleAlert className="size-5" />
        </span>
        <div className="space-y-1.5">
          <h1 className="text-base font-semibold text-white">This view could not load</h1>
          <p className="text-xs leading-5 text-white/45">
            The rest of the workspace is still available. Try again — if it keeps
            failing, the reference below identifies this exact failure in the logs.
          </p>
        </div>
        {error.digest ? (
          <p className="font-mono text-[10px] text-white/30">Reference {error.digest}</p>
        ) : null}
        <Button onClick={reset} className="w-full">
          <RotateCcw className="mr-1.5 size-3.5" />
          Try again
        </Button>
      </div>
    </div>
  );
}
