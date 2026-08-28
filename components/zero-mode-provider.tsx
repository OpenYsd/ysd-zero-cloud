'use client';

import { createContext, useContext, useMemo, useState } from 'react';

type ZeroModeContextValue = {
  enabled: boolean;
  setEnabled: (enabled: boolean) => void;
};

const ZeroModeContext = createContext<ZeroModeContextValue | null>(null);

export function ZeroModeProvider({ children }: { children: React.ReactNode }) {
  const [enabled, setEnabled] = useState(true);

  const value = useMemo(
    () => ({
      enabled,
      setEnabled(next: boolean) {
        setEnabled(next);
        window.localStorage.setItem('ysd-zero-mode', String(next));
      },
    }),
    [enabled],
  );

  return <ZeroModeContext.Provider value={value}>{children}</ZeroModeContext.Provider>;
}

export function useZeroMode() {
  const context = useContext(ZeroModeContext);
  if (!context) throw new Error('useZeroMode must be used inside ZeroModeProvider');
  return context;
}
