import { createId } from '@/lib/crypto';
import type { Project } from '@/lib/domain';
import { detectFramework, type Framework } from '@/lib/smart-deploy';
import { count, execute, query, queryOne } from './db';
import { writeLog } from './logs';

/**
 * Projects are the unit Smart Deploy targets. A deployment can create one
 * implicitly, which keeps the first run of a fresh workspace to a single step.
 */

export type { Project };

export const MAX_PROJECTS = 25;

/** Project names become part of a URL, so the accepted shape is narrow. */
export function normalizeProjectName(input: string): string {
  return input
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-_]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
}

export function projectNameFromRepository(repository: string): string {
  const tail = repository.split('/').pop() ?? repository;
  return normalizeProjectName(tail) || 'project';
}

export async function listProjects(workspaceId: string): Promise<Project[]> {
  return query<Project>(
    `SELECT id, name, repository, framework, environment, region, status, visibility, createdAt, updatedAt
     FROM project WHERE workspaceId = ? ORDER BY updatedAt DESC`,
    workspaceId,
  );
}

export async function getProject(workspaceId: string, id: string): Promise<Project | null> {
  return queryOne<Project>(
    `SELECT id, name, repository, framework, environment, region, status, visibility, createdAt, updatedAt
     FROM project WHERE workspaceId = ? AND id = ?`,
    workspaceId,
    id,
  );
}

export async function findProjectByName(
  workspaceId: string,
  name: string,
): Promise<Project | null> {
  return queryOne<Project>(
    `SELECT id, name, repository, framework, environment, region, status, visibility, createdAt, updatedAt
     FROM project WHERE workspaceId = ? AND name = ?`,
    workspaceId,
    name,
  );
}

export async function countProjects(workspaceId: string): Promise<number> {
  return count('SELECT COUNT(*) AS total FROM project WHERE workspaceId = ?', workspaceId);
}

export type CreateProjectInput = {
  workspaceId: string;
  actor: string;
  name: string;
  repository?: string | null;
  framework?: Framework;
  environment?: string;
  region?: string;
  visibility?: Project['visibility'];
};

export type CreateProjectResult =
  | { ok: true; project: Project }
  | { ok: false; error: string; status: number };

export async function createProject(input: CreateProjectInput): Promise<CreateProjectResult> {
  const name = normalizeProjectName(input.name);
  if (!name) {
    return { ok: false, error: 'A project name is required.', status: 400 };
  }

  const existing = await findProjectByName(input.workspaceId, name);
  if (existing) {
    return { ok: false, error: `A project called "${name}" already exists.`, status: 409 };
  }

  // The ceiling is the free-tier allowance, not a paywall: there is no plan to
  // upgrade to, so the workspace simply stops accepting new projects.
  if ((await countProjects(input.workspaceId)) >= MAX_PROJECTS) {
    return {
      ok: false,
      error: `The free tier allows ${MAX_PROJECTS} projects. Delete one to add another.`,
      status: 409,
    };
  }

  const now = Date.now();
  const project: Project = {
    id: createId('prj'),
    name,
    repository: input.repository?.trim() || null,
    framework: input.framework ?? detectFramework(input.repository ?? name),
    environment: input.environment?.trim() || 'Production',
    region: input.region?.trim() || 'Global Edge',
    status: 'idle',
    visibility: input.visibility ?? 'private',
    createdAt: now,
    updatedAt: now,
  };

  await execute(
    `INSERT INTO project (id, workspaceId, name, repository, framework, environment, region, status, visibility, createdAt, updatedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    project.id,
    input.workspaceId,
    project.name,
    project.repository,
    project.framework,
    project.environment,
    project.region,
    project.status,
    project.visibility,
    project.createdAt,
    project.updatedAt,
  );

  await writeLog({
    workspaceId: input.workspaceId,
    source: 'project',
    message: `Project ${project.name} created`,
    actor: input.actor,
    resource: project.id,
  });

  return { ok: true, project };
}

export async function setProjectStatus(
  workspaceId: string,
  projectId: string,
  status: Project['status'],
): Promise<void> {
  await execute(
    'UPDATE project SET status = ?, updatedAt = ? WHERE workspaceId = ? AND id = ?',
    status,
    Date.now(),
    workspaceId,
    projectId,
  );
}

export async function deleteProject(
  workspaceId: string,
  projectId: string,
  actor: string,
): Promise<boolean> {
  const project = await getProject(workspaceId, projectId);
  if (!project) return false;
  await execute('DELETE FROM project WHERE workspaceId = ? AND id = ?', workspaceId, projectId);
  await writeLog({
    workspaceId,
    source: 'project',
    level: 'WARN',
    message: `Project ${project.name} deleted`,
    actor,
    resource: projectId,
  });
  return true;
}
