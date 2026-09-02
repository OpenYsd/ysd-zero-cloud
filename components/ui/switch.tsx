'use client';

import { Switch as SwitchPrimitive } from '@base-ui/react/switch';

import { cn } from '@/lib/utils';

/**
 * Switch with a caller-supplied, deterministic DOM id.
 *
 * `id` is required, and that is the point. Base UI's `SwitchRoot` gives its root
 * element `base-ui-${React.useId()}` and offers no way to override it: the `id`
 * prop is consumed for the hidden input instead, and with the default
 * `nativeButton={false}` the root always receives the generated value. React's
 * `useId` encodes a component's position in the tree, and under this framework's
 * RSC setup the server tree and the hydrating client tree are not the same
 * shape — server components are real components during the server render and
 * already-resolved output on the client. The two sides therefore computed
 * different ids for the same control, and React reported a hydration mismatch
 * on every authenticated page load, which it explicitly does not patch up.
 *
 * Pinning the id removes the nondeterminism rather than hiding it: no
 * `suppressHydrationWarning` anywhere, so a genuine mismatch would still be
 * reported. The root id is supplied through `render`, the only channel Base UI
 * leaves open for it, and the hidden input takes `${id}-control` through the
 * `id` prop so the two elements stay distinct.
 *
 * Requiring the prop is what stops this returning: a new Switch does not
 * type-check until it is given a stable id.
 */
function Switch({
  className,
  size = 'default',
  id,
  ...props
}: Omit<SwitchPrimitive.Root.Props, 'id' | 'render'> & {
  size?: 'sm' | 'default';
  /** Stable across server and client, and unique within the page. */
  id: string;
}) {
  return (
    <SwitchPrimitive.Root
      render={<span id={id} />}
      id={`${id}-control`}
      data-slot="switch"
      data-size={size}
      className={cn(
        'peer group/switch relative inline-flex shrink-0 items-center rounded-full border border-transparent transition-all outline-none group-has-[:focus-visible]/field-label:border-transparent group-has-[:focus-visible]/field-label:ring-0 after:absolute after:-inset-x-3 after:-inset-y-2 focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 data-[size=default]:h-[18.4px] data-[size=default]:w-[32px] data-[size=sm]:h-[14px] data-[size=sm]:w-[24px] dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40 data-checked:bg-primary data-unchecked:bg-input dark:data-unchecked:bg-input/80 data-disabled:cursor-not-allowed data-disabled:opacity-50',
        className,
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb
        data-slot="switch-thumb"
        className="pointer-events-none block rounded-full bg-background ring-0 transition-transform group-data-[size=default]/switch:size-4 group-data-[size=sm]/switch:size-3 group-data-[size=default]/switch:data-checked:translate-x-[calc(100%-2px)] group-data-[size=sm]/switch:data-checked:translate-x-[calc(100%-2px)] dark:data-checked:bg-primary-foreground group-data-[size=default]/switch:data-unchecked:translate-x-0 group-data-[size=sm]/switch:data-unchecked:translate-x-0 dark:data-unchecked:bg-foreground"
      />
    </SwitchPrimitive.Root>
  );
}

export { Switch };
