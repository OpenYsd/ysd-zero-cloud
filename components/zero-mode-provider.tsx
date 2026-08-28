'use client';

import { createContext, useCallback, useContext, useMemo, useState, useTransition } from 'react';

/**
 * Zero Mode state for the browser.
 *
 * The workspace row is the source of truth. This provider holds the server
 * value, sends changes to `/api/settings`, and rolls back if the write fails
 * so the switch can never show a guarantee the server is not making.
 */

type ZeroModeContextValue = {
  enabled: boolean;
  pending: boolean;
  error: string | null;
  setEnabled: (enabled: boolean) => void;
};

const ZeroModeContext = createContext<ZeroModeContextValue | null>(null);

export function ZeroModeProvider({
  children,
  initialEnabled,
  /** False on the sign-in screens, where there is no workspace to write to. */
  persist = true,
}: {
  children: React.ReactNode;
  initialEnabled: boolean;
  persist?: boolean;
}) {
  const [enabled, setEnabledState] = useState(initialEnabled);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const setEnabled = useCallback(
    (next: boolean) => {
      const previous = enabled;
      setEnabledState(next);
      setError(null);
      if (!persist) return;

      startTransition(async () => {
        try {
          const response = await fetch('/api/settings', {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ setting: 'zeroMode', value: next }),
          });
          if (!response.ok) {
            const body = (await response.json().catch(() => ({}))) as { error?: string };
            throw new Error(body.error ?? 'The setting could not be saved.');
          }
        } catch (cause) {
          setEnabledState(previous);
          setError(cause instanceof Error ? cause.message : 'The setting could not be saved.');
        }
      });
    },
    [enabled, persist],
  );

  const value = useMemo(
    () => ({ enabled, pending, error, setEnabled }),
    [enabled, pending, error, setEnabled],
  );

  return <ZeroModeContext.Provider value={value}>{children}</ZeroModeContext.Provider>;
}

export function useZeroMode() {
  const context = useContext(ZeroModeContext);
  if (!context) throw new Error('useZeroMode must be used inside ZeroModeProvider');
  return context;
}
