import type { AnchorHTMLAttributes } from 'react';

/**
 * Internal navigation link.
 *
 * This renders a plain anchor instead of `next/link`, deliberately.
 *
 * vinext's client Link runtime is broken in its production bundle. On click the
 * handler calls `preventDefault()` and then:
 *
 *     const { navigateClientSide } = loadedNavigationModule ?? await load();
 *     startTransition(() => navigateClientSide(...));
 *
 * `navigateClientSide` comes back `undefined`, because the chunk it is
 * dynamically imported from never exports it under that name — the bundler
 * mangles the export list to single letters and the by-name destructure finds
 * nothing. The call throws inside `startTransition`, and the
 * `window.location.assign` fallback sits in an `else` branch that is never
 * reached. The browser's own navigation has already been cancelled by then, so
 * every link in the application is inert. Reproduced on the deployed Worker in
 * both vinext 1.0.0-beta.5 and 1.0.0-beta.8.
 *
 * A native anchor cannot fail this way: no JavaScript participates, so the
 * browser navigates. The cost is a full document load per navigation instead of
 * an RSC transition, which this application can afford — none of its pages
 * carry client state that must survive a navigation.
 *
 * When vinext ships a working Link, the whole change reverts by pointing this
 * component at `next/link`; nothing else in the app has to move.
 */
export function NavLink({
  href,
  children,
  ...rest
}: { href: string } & Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'href'>) {
  return (
    <a href={href} {...rest}>
      {children}
    </a>
  );
}
