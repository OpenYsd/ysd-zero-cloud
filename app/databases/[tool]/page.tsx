import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { DatabaseWorkspace } from '@/components/database-workspace';
import { requireSession } from '@/lib/server/session';
import { listTables } from '@/lib/server/studio';

export const dynamic = 'force-dynamic';

const TOOLS = { studio: 'Database Studio', 'sql-editor': 'SQL Editor' } as const;

type Tool = keyof typeof TOOLS;

function isTool(value: string): value is Tool {
  return value in TOOLS;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ tool: string }>;
}): Promise<Metadata> {
  const { tool } = await params;
  return { title: isTool(tool) ? TOOLS[tool] : 'Not found' };
}

export default async function DatabaseToolPage({ params }: { params: Promise<{ tool: string }> }) {
  const { tool } = await params;
  if (!isTool(tool)) notFound();

  await requireSession();
  const tables = await listTables();

  // Opening on a workspace table rather than an auth table keeps the first
  // screen useful and keeps redacted columns out of the default view.
  const firstWorkspaceTable = tables.find((table) => table.kind === 'workspace');

  return (
    <DatabaseWorkspace
      mode={tool}
      tables={tables}
      initialTable={firstWorkspaceTable?.name ?? tables[0]?.name ?? null}
    />
  );
}
