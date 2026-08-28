'use client';

import { useEffect, useRef, useState } from 'react';

/**
 * The Cloudflare Turnstile challenge.
 *
 * Renders nothing when no site key is configured, which is the same condition
 * under which the server skips verification — so the widget and the check can
 * never disagree about whether the challenge is in play.
 *
 * The script is loaded on demand rather than in the document head: it is only
 * needed on two screens, and an auth page should not pull a third-party script
 * on an instance that has not enabled the challenge.
 */

declare global {
  interface Window {
    turnstile?: {
      render: (
        el: HTMLElement,
        options: {
          sitekey: string;
          callback: (token: string) => void;
          'error-callback'?: () => void;
          'expired-callback'?: () => void;
          theme?: 'auto' | 'light' | 'dark';
        },
      ) => string;
      reset: (id?: string) => void;
      remove: (id?: string) => void;
    };
  }
}

const SCRIPT_SRC = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
const SCRIPT_ID = 'cf-turnstile-script';

function loadScript(): Promise<void> {
  if (typeof window === 'undefined') return Promise.resolve();
  if (window.turnstile) return Promise.resolve();

  const existing = document.getElementById(SCRIPT_ID) as HTMLScriptElement | null;
  if (existing) {
    return new Promise((resolve) => existing.addEventListener('load', () => resolve(), { once: true }));
  }

  return new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.id = SCRIPT_ID;
    script.src = SCRIPT_SRC;
    script.async = true;
    script.defer = true;
    script.addEventListener('load', () => resolve(), { once: true });
    script.addEventListener('error', () => reject(new Error('Turnstile failed to load')), { once: true });
    document.head.appendChild(script);
  });
}

export function TurnstileWidget({
  siteKey,
  onToken,
}: {
  siteKey: string | null;
  onToken: (token: string) => void;
}) {
  const container = useRef<HTMLDivElement | null>(null);
  const widgetId = useRef<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!siteKey) return;
    let cancelled = false;

    void loadScript()
      .then(() => {
        if (cancelled || !container.current || !window.turnstile) return;
        widgetId.current = window.turnstile.render(container.current, {
          sitekey: siteKey,
          theme: 'dark',
          callback: (token) => onToken(token),
          // An expired or failed challenge clears the token, so the form
          // cannot submit a stale one that the server would reject anyway.
          'expired-callback': () => onToken(''),
          'error-callback': () => {
            onToken('');
            setFailed(true);
          },
        });
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });

    return () => {
      cancelled = true;
      if (widgetId.current && window.turnstile) {
        try {
          window.turnstile.remove(widgetId.current);
        } catch {
          // The widget may already be gone with the DOM node.
        }
      }
    };
  }, [siteKey, onToken]);

  if (!siteKey) return null;

  return (
    <div className="space-y-2">
      <div ref={container} className="flex justify-center" />
      {failed && (
        <p className="text-center text-[10px] text-amber-300/80">
          The challenge could not load. Check your connection and reload.
        </p>
      )}
    </div>
  );
}
