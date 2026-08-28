import { notFound } from 'next/navigation';
import { DatabaseWorkspace } from '@/components/database-workspace';

export default async function DatabaseToolPage({ params }: { params: Promise<{ tool: string }> }) {
  const { tool } = await params;
  if (tool !== 'studio' && tool !== 'sql-editor') notFound();
  return <DatabaseWorkspace mode={tool} />;
}
