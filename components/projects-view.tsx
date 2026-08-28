'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { Box, GitBranch, Loader2, Plus, Trash2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { EmptyState } from '@/components/ui-bits';
import { relativeTime } from '@/lib/format';
import type { Project } from '@/lib/domain';

const STATUS_TONE: Record<Project['status'], string> = {
  live: 'border-[#b7ff3c]/15 bg-[#b7ff3c]/5 text-[#c8ff69]',
  building: 'border-[#4ac7ff]/15 bg-[#4ac7ff]/5 text-[#79d6ff]',
  idle: 'border-white/[0.08] text-white/40',
  blocked: 'border-amber-400/20 bg-amber-400/5 text-amber-300',
};

export function ProjectsView({ projects, now }: { projects: Project[]; now: number }) {
  const router = useRouter();
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [repository, setRepository] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);

  async function create(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      const response = await fetch('/api/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, repository: repository.trim() || null }),
      });
      const body = (await response.json()) as { error?: string };
      if (!response.ok) throw new Error(body.error ?? 'The project could not be created.');
      setName('');
      setRepository('');
      setCreating(false);
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The project could not be created.');
    } finally {
      setPending(false);
    }
  }

  async function remove(id: string) {
    setRemoving(id);
    try {
      await fetch(`/api/projects/${id}`, { method: 'DELETE' });
      router.refresh();
    } finally {
      setRemoving(null);
    }
  }

  return (
    <>
      <div className="flex justify-end">
        <Button
          onClick={() => setCreating((open) => !open)}
          className="h-9 bg-[#b7ff3c] px-3.5 text-xs font-semibold text-[#07100c] hover:bg-[#cbff72]"
        >
          <Plus /> New project
        </Button>
      </div>

      {creating && (
        <form onSubmit={create} className="cloud-card grid gap-4 p-5 lg:grid-cols-[1fr_1fr_auto] lg:items-end">
          <div className="space-y-1.5">
            <Label htmlFor="project-name" className="text-[11px] text-white/45">Name</Label>
            <Input
              id="project-name"
              required
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="my-service"
              className="h-9 border-white/[0.08] bg-black/15 text-xs"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="project-repository" className="text-[11px] text-white/45">Repository (optional)</Label>
            <div className="relative">
              <GitBranch className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-white/25" />
              <Input
                id="project-repository"
                value={repository}
                onChange={(event) => setRepository(event.target.value)}
                placeholder="owner/repo"
                className="h-9 border-white/[0.08] bg-black/15 pl-9 text-xs"
              />
            </div>
          </div>
          <Button type="submit" disabled={pending} className="h-9 bg-[#7569ff] text-xs text-white hover:bg-[#887eff]">
            {pending ? <Loader2 className="animate-spin" /> : <Plus />} Create
          </Button>
          {error && (
            <p role="alert" className="text-[11px] text-red-300 lg:col-span-3">
              {error}
            </p>
          )}
        </form>
      )}

      {projects.length === 0 ? (
        <EmptyState
          title="No projects yet"
          copy="Create one here, or let Smart Deploy create it from a repository when a plan clears the cost guard."
        />
      ) : (
        <section className="cloud-card overflow-hidden">
          <Table className="text-[11px]">
            <TableHeader>
              <TableRow className="border-white/[0.06] hover:bg-transparent">
                {['Project', 'Framework', 'Repository', 'Environment', 'Region', 'Status', 'Updated', ''].map((column, index) => (
                  <TableHead key={column || `actions-${index}`} className="h-9 px-4 text-[9px] uppercase tracking-[0.1em] text-white/25">
                    {column}
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {projects.map((project) => (
                <TableRow key={project.id} className="border-white/[0.05] hover:bg-white/[0.02]">
                  <TableCell className="px-4 py-3">
                    <span className="flex items-center gap-2 font-medium text-white/72">
                      <Box className="size-3.5 text-[#b7ff3c]/65" />
                      {project.name}
                    </span>
                  </TableCell>
                  <TableCell className="px-4 py-3 text-white/42">{project.framework}</TableCell>
                  <TableCell className="px-4 py-3 font-mono text-[10px] text-white/35">{project.repository ?? '—'}</TableCell>
                  <TableCell className="px-4 py-3 text-white/42">{project.environment}</TableCell>
                  <TableCell className="px-4 py-3 text-white/42">{project.region}</TableCell>
                  <TableCell className="px-4 py-3">
                    <Badge variant="outline" className={STATUS_TONE[project.status]}>{project.status}</Badge>
                  </TableCell>
                  <TableCell className="px-4 py-3 text-white/42">{relativeTime(project.updatedAt, now)}</TableCell>
                  <TableCell className="px-4 py-3 text-right">
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      aria-label={`Delete ${project.name}`}
                      disabled={removing === project.id}
                      onClick={() => remove(project.id)}
                    >
                      {removing === project.id ? <Loader2 className="animate-spin" /> : <Trash2 />}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </section>
      )}
    </>
  );
}
