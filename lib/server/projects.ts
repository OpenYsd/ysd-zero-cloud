import { createId } from '@/lib/crypto';
import type { Project } from '@/lib/domain';
import { detectFramework, type Framework } from '@/lib/smart-deploy';
import {
  buildReadinessReport,
  parseReadinessReport,
  readinessSummary,
  serializeReadinessReport,
  type ReadinessReport,
} from '@/lib/readiness';
import { hasGithubToken } from '@/lib/integrations';
import { env } from 'cloudflare:workers';
import { count, execute, query, queryOne } from './db';
import { runtimeEnv } from './env';
import { inspectRepositoryForDeploy } from './github';
import { writeLog } from './logs';
import { assertResourceCapacity } from './organization-limits';

/**
 * Projects are the unit Smart Deploy targets. A deployment can create one
 * implicitly, which keeps the first run of a fresh workspace to a single step.
 */

export type { Project };

export const MAX_PROJECTS = 25;

/**
 * The columns every project read selects. Readiness travels as the six
 * denormalised summary columns, never the stored report -- the report is
 * parsed only in `getProjectReadinessReport`, for the one caller that needs
 * the full detail. This is what keeps the list a single bounded statement
 * regardless of how many projects a workspace has.
 */
const PROJECT_COLUMNS = `id, name, repository, framework, environment, region, status, visibility, createdAt, updatedAt,
     readinessAnalyzedAt, readinessCommit, readinessFramework, readinessBlockedCount, readinessSourceBranch`;

type ProjectRow = Omit<Project, 'readiness'> & {
  readinessAnalyzedAt: number | null;
  readinessCommit: string | null;
  readinessFramework: string | null;
  readinessBlockedCount: number | null;
  readinessSourceBranch: string | null;
};

function toProject(row: ProjectRow): Project {
  const { readinessAnalyzedAt, readinessCommit, readinessFramework, readinessBlockedCount, readinessSourceBranch, ...base } = row;
  return {
    ...base,
    readiness: readinessSummary({
      readinessAnalyzedAt,
      readinessCommit,
      readinessFramework,
      readinessBlockedCount,
      readinessSourceBranch,
    }),
  };
}

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

export async function listProjects(
  workspaceId: string,
  projectIds?: readonly string[] | null,
): Promise<Project[]> {
  if (projectIds !== null && projectIds !== undefined && projectIds.length === 0) return [];
  const restricted = projectIds !== null && projectIds !== undefined;
  const rows = await query<ProjectRow>(
    `SELECT ${PROJECT_COLUMNS}
     FROM project WHERE workspaceId = ?${restricted ? ` AND id IN (${projectIds.map(() => '?').join(', ')})` : ''}
     ORDER BY updatedAt DESC`,
    workspaceId,
    ...(projectIds ?? []),
  );
  return rows.map(toProject);
}

export async function getProject(
  workspaceId: string,
  id: string,
  projectIds?: readonly string[] | null,
): Promise<Project | null> {
  if (projectIds !== null && projectIds !== undefined && !projectIds.includes(id)) return null;
  const row = await queryOne<ProjectRow>(
    `SELECT ${PROJECT_COLUMNS}
     FROM project WHERE workspaceId = ? AND id = ?`,
    workspaceId,
    id,
  );
  return row ? toProject(row) : null;
}

export async function findProjectByName(
  workspaceId: string,
  name: string,
): Promise<Project | null> {
  const row = await queryOne<ProjectRow>(
    `SELECT ${PROJECT_COLUMNS}
     FROM project WHERE workspaceId = ? AND name = ?`,
    workspaceId,
    name,
  );
  return row ? toProject(row) : null;
}

export async function countProjects(
  workspaceId: string,
  projectIds?: readonly string[] | null,
): Promise<number> {
  if (projectIds !== null && projectIds !== undefined) return projectIds.length;
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
  const capacity = await assertResourceCapacity(input.workspaceId, 'projects');
  if (!capacity.ok) return { ok: false, error: capacity.error, status: 409 };

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
    // A new project has never been analyzed; the readiness columns are NULL
    // until `analyzeProjectReadiness` runs.
    readiness: readinessSummary({}),
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
  projectIds?: readonly string[] | null,
): Promise<boolean> {
  const project = await getProject(workspaceId, projectId, projectIds);
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

export type AnalyzeReadinessOutcome =
  | { ok: true; report: ReadinessReport; owner: string; repository: string }
  | { ok: false; status: number; error: string; projectNotFound?: true };

/**
 * Analysis, never execution.
 *
 * This reuses the same `inspectRepositoryForDeploy` the deployment path calls
 * -- the identical GitHub-only reader, the identical bounded analyzer -- and
 * stops exactly where analysis ends: a stored verdict and a priced,
 * unexecuted resource preview. It never touches `deployment`, never selects or
 * contacts a Compute Node, and never creates a node job. A Compute Node
 * remains mandatory for every build, execution, and runtime action; nothing
 * here weakens that.
 */
export async function analyzeProjectReadiness(input: {
  workspaceId: string;
  projectId: string;
  projectIds?: readonly string[] | null;
}): Promise<AnalyzeReadinessOutcome> {
  const project = await getProject(input.workspaceId, input.projectId, input.projectIds);
  // Distinguished from every other failure below by `projectNotFound`, not by
  // its status code: GitHub's own inspection can independently fail with a
  // 404-shaped error (repository renamed, rate-limited, transient), and that
  // case must still be recorded as evidence -- the project genuinely exists
  // and belongs to this tenant. Only this branch is the opaque, unrecorded
  // "does this project exist" answer.
  if (!project) return { ok: false, status: 404, error: 'Project not found.', projectNotFound: true };
  if (!project.repository) {
    return { ok: false, status: 409, error: 'This project has no repository to analyze.' };
  }

  const token = hasGithubToken(runtimeEnv) ? env.GITHUB_TOKEN : undefined;
  const inspection = await inspectRepositoryForDeploy({
    repository: project.repository,
    token,
  });
  if (!inspection.ok) return inspection;

  const { source, analysis } = inspection.value;
  const report = buildReadinessReport({
    analysis,
    commit: source.commit,
    branch: source.branch,
    zeroModeEnabled: true,
  });
  const { json } = serializeReadinessReport(report);

  await execute(
    `UPDATE project
        SET readinessAnalyzedAt = ?, readinessCommit = ?, readinessFramework = ?,
            readinessBlockedCount = ?, readinessReport = ?, readinessSourceBranch = ?,
            updatedAt = ?
      WHERE workspaceId = ? AND id = ?`,
    Date.now(),
    report.commit,
    report.framework,
    report.blockedCount,
    json,
    report.branch,
    Date.now(),
    input.workspaceId,
    input.projectId,
  );

  await writeLog({
    workspaceId: input.workspaceId,
    source: 'project',
    message: `Readiness ${report.verdict} for ${project.name} at ${report.commit.slice(0, 7)}`,
    resource: input.projectId,
  });

  return { ok: true, report, owner: source.owner, repository: source.repository };
}

/**
 * The full stored report, for the one caller that needs blocker detail: the
 * project detail view. The list never calls this -- it reads the
 * denormalised summary columns instead, which is what keeps it O(1).
 */
export async function getProjectReadinessReport(
  workspaceId: string,
  projectId: string,
  projectIds?: readonly string[] | null,
): Promise<ReadinessReport | null> {
  if (projectIds !== null && projectIds !== undefined && !projectIds.includes(projectId)) return null;
  const row = await queryOne<{ readinessReport: string | null }>(
    'SELECT readinessReport FROM project WHERE workspaceId = ? AND id = ?',
    workspaceId,
    projectId,
  );
  return row ? parseReadinessReport(row.readinessReport) : null;
}
