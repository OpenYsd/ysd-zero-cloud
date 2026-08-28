import { FlaskConical } from 'lucide-react';

/**
 * Small presentational pieces shared across the section surfaces.
 *
 * They live in one file so a change to, say, how an empty state looks lands
 * everywhere at once rather than drifting per page.
 */

export function PageHeader({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow: string;
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <header className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
      <div>
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-[#b7ff3c]/55">{eyebrow}</p>
        <h1 className="text-2xl font-semibold tracking-[-0.035em] text-white sm:text-[28px]">{title}</h1>
        <p className="mt-1.5 text-xs text-white/34">{description}</p>
      </div>
      {action}
    </header>
  );
}

/**
 * Marks a surface that is not yet backed by real data.
 *
 * The app would rather show a labelled preview than a convincing screen of
 * numbers nobody can act on.
 */
export function PreviewNotice({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2.5 rounded-xl border border-[#4ac7ff]/12 bg-[#4ac7ff]/[0.035] p-4 text-[11px] leading-5 text-white/42">
      <FlaskConical className="mt-px size-3.5 shrink-0 text-[#79d6ff]" />
      <span>{children}</span>
    </div>
  );
}

export function EmptyState({
  title,
  copy,
  action,
}: {
  title: string;
  copy: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="cloud-card grid place-items-center px-6 py-14 text-center">
      <div>
        <p className="text-xs font-semibold text-white/60">{title}</p>
        <p className="mx-auto mt-1.5 max-w-sm text-[11px] leading-5 text-white/28">{copy}</p>
        {action ? <div className="mt-4 flex justify-center">{action}</div> : null}
      </div>
    </div>
  );
}

export function SmallMetric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-[9px] uppercase tracking-[0.1em] text-white/22">{label}</p>
      <p className="mt-1.5 text-xs font-semibold text-white/60">{value}</p>
    </div>
  );
}

export function MetricGrid({
  items,
}: {
  items: { icon: React.ComponentType<{ className?: string }>; label: string; value: string; detail: string }[];
}) {
  return (
    <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      {items.map((item, index) => {
        const Icon = item.icon;
        return (
          <article key={item.label} className="cloud-card p-4">
            <div className={index % 3 === 0 ? 'icon-well icon-well-lime' : index % 3 === 1 ? 'icon-well icon-well-violet' : 'icon-well icon-well-blue'}>
              <Icon className="size-4" />
            </div>
            <p className="mt-4 text-2xl font-semibold tracking-[-0.04em] text-white">{item.value}</p>
            <div className="mt-1 flex justify-between text-xs">
              <span className="text-white/55">{item.label}</span>
              <span className="text-white/25">{item.detail}</span>
            </div>
          </article>
        );
      })}
    </section>
  );
}
