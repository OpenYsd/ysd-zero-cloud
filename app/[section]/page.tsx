import type { Metadata } from 'next';
import { notFound, redirect } from 'next/navigation';
import { AiCenter } from '@/components/ai-center';
import { GameServersView } from '@/components/game-servers-view';
import { LogsView } from '@/components/logs-view';
import { NetworkingView } from '@/components/networking-view';
import { NodesView } from '@/components/nodes-view';
import { ProjectsView } from '@/components/projects-view';
import { StorageView } from '@/components/storage-view';
import {
  DatabasesOverview,
  DeploymentsList,
  isSection,
  PreviewSection,
  SECTION_META,
  UsageView,
  type Section,
} from '@/components/section-dashboard';
import { SecretsView } from '@/components/secrets-view';
import { SettingsView } from '@/components/settings-view';
import { ShieldView } from '@/components/shield-view';
import { SmartDeployPanel } from '@/components/smart-deploy-panel';
import { WorkflowsView } from '@/components/workflows-view';
import { IncidentsView } from '@/components/incidents-view';
import { CapacityView } from '@/components/capacity-view';
import {
  AuditView,
  InvitationsView,
  MembersView,
  ServiceAccountsView,
  SessionsView,
} from '@/components/collaboration-views';
import { PageHeader } from '@/components/ui-bits';
import type { Organization, Workspace } from '@/lib/domain';
import type { Actor } from '@/lib/roles';
import { FREE_TIER_LIMITS } from '@/lib/free-tier';
import { getIntegrationCatalog } from '@/lib/integrations';
import { can } from '@/lib/roles';
import { requestTime } from '@/lib/server/clock';
import { readAiState } from '@/lib/server/ai';
import { readGameServersState } from '@/lib/server/game-servers';
import { listDeployments } from '@/lib/server/deployments';
import { runtimeEnv } from '@/lib/server/env';
import { listLogs } from '@/lib/server/logs';
import { readNetworkState } from '@/lib/server/networking';
import { readNodesState } from '@/lib/server/nodes';
import { listProjects } from '@/lib/server/projects';
import { listSecrets } from '@/lib/server/secrets';
import { requireSession } from '@/lib/server/session';
import { readShieldState } from '@/lib/server/shield-scan';
import { databaseBytes, listTables } from '@/lib/server/studio';
import { listStorage } from '@/lib/server/storage';
import { summarizeUsage } from '@/lib/server/usage';
import { listInvitations, listMembers } from '@/lib/server/organizations';
import { listServiceAccounts } from '@/lib/server/service-accounts';
import { listAuditEvents } from '@/lib/server/audit';
import { listOwnSessions } from '@/lib/server/devices';
import { readCollaborationLimits } from '@/lib/server/organization-limits';
import { listWorkflowsState } from '@/lib/server/workflows';
import { listIncidentState } from '@/lib/server/incidents';
import { listDataLifecycleState } from '@/lib/server/retention';
import { parseIncidentFilters } from '@/lib/incidents';

export const dynamic = 'force-dynamic';

export async function generateMetadata({
  params,
}: {
  params: Promise<{ section: string }>;
}): Promise<Metadata> {
  const { section } = await params;
  return {
    title: isSection(section) ? SECTION_META[section].title : 'Not found',
  };
}

export default async function SectionPage({
  params,
  searchParams,
}: {
  params: Promise<{ section: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { section } = await params;
  const search = await searchParams;
  if (!isSection(section)) notFound();

  const { organization, workspace, actor, user } = await requireSession();

  // The admin surface is not merely hidden from the navigation: reaching it
  // directly without the capability sends the visitor back to the overview.
  if (section === 'admin') redirect('/members');

  const permissions = {
    projects: 'project.read', deployments: 'deployment.read', databases: 'database.read',
    storage: 'storage.read', ai: 'ai.read', 'game-servers': 'game-server.read',
    nodes: 'node.read', logs: 'workspace.read', networking: 'workspace.read',
    secrets: 'secret.metadata.read', workflows: 'workflow.read', incidents: 'incident.read', usage: 'usage.read', shield: 'shield.read',
    members: 'member.read', invitations: 'invitation.read',
    'service-accounts': 'service-account.read', audit: 'audit.read',
    sessions: 'session.read-own', settings: 'workspace.update', admin: 'member.read',
  } as const;
  if (!can(actor, permissions[section])) notFound();

  const meta = SECTION_META[section];
  const now = await requestTime();

  return (
    <div className="mx-auto w-full max-w-[1440px] space-y-5">
      <PageHeader
        eyebrow={meta.eyebrow}
        title={meta.title}
        description={meta.description}
      />
      <SectionBody
        section={section}
        workspace={workspace}
        organization={organization}
        actor={actor}
        userId={user.id}
        now={now}
        search={search}
      />
    </div>
  );
}

async function SectionBody({
  section,
  workspace,
  organization,
  actor,
  userId,
  now,
  search,
}: {
  section: Section;
  workspace: Workspace;
  organization: Organization;
  actor: Actor;
  userId: string;
  now: number;
  search: Record<string, string | string[] | undefined>;
}) {
  const workspaceId = workspace.id;

  switch (section) {
    case 'projects':
      return (
        <ProjectsView projects={await listProjects(workspaceId, actor.projectIds)} now={now} />
      );

    case 'deployments': {
      const [deployments, nodes] = await Promise.all([
        listDeployments(workspaceId, 50, actor.projectIds),
        readNodesState(workspaceId, now),
      ]);
      return (
        <>
          <SmartDeployPanel nodes={nodes.nodes} />
          <DeploymentsList
            deployments={deployments}
            now={now}
          />
        </>
      );
    }

    case 'databases': {
      const [tables, bytes] = await Promise.all([
        listTables({
          organizationId: organization.id,
          workspaceId,
          userId,
          projectIds: actor.projectIds,
        }),
        databaseBytes(),
      ]);
      const limit =
        FREE_TIER_LIMITS.find((entry) => entry.id === 'database-bytes')
          ?.limit ?? 0;
      return (
        <DatabasesOverview tables={tables} bytes={bytes} limitBytes={limit} />
      );
    }

    case 'logs':
      return (
        <LogsView initialEvents={await listLogs(workspaceId, { limit: 100 }, actor.projectIds)} />
      );

    case 'storage':
      return <StorageView state={await listStorage(workspaceId)} now={now} />;

    case 'networking':
      return (
        <NetworkingView
          state={await readNetworkState({
            organizationId: organization.id,
            workspaceId,
            actor,
          })}
        />
      );

    case 'nodes':
      return (
        <NodesView state={await readNodesState(workspaceId, now)} now={now} />
      );

    case 'ai':
      return <AiCenter state={await readAiState(workspaceId, now)} now={now} />;

    case 'game-servers':
      return (
        <GameServersView
          state={await readGameServersState(workspaceId, now)}
          now={now}
        />
      );

    case 'secrets':
      return <SecretsView secrets={await listSecrets(workspaceId, actor.projectIds)} now={now} />;

    case 'workflows': {
      const [state, projects, secrets] = await Promise.all([
        listWorkflowsState({
          organizationId: organization.id,
          workspaceId,
          actor,
          userId,
        }),
        listProjects(workspaceId, actor.projectIds),
        listSecrets(workspaceId, actor.projectIds),
      ]);
      return (
        <WorkflowsView
          state={state}
          actor={{ userId, role: actor.role }}
          projects={projects}
          secrets={secrets}
          now={now}
        />
      );
    }

    case 'incidents': {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(search)) {
        if (typeof value === 'string') params.set(key, value);
      }
      const [state, members, projects] = await Promise.all([
        listIncidentState({ workspaceId, actor, filters: parseIncidentFilters(params) }),
        listMembers(organization.id, workspaceId),
        listProjects(workspaceId, actor.projectIds),
      ]);
      return (
        <IncidentsView
          initialState={state}
          members={members}
          projects={projects}
          canManage={can(actor, 'incident.manage')}
          canResolveCritical={can(actor, 'incident.resolve-critical')}
          now={now}
        />
      );
    }

    case 'usage': {
      const [usage, collaboration] = await Promise.all([
        summarizeUsage(workspaceId, userId, {
          organizationId: organization.id,
          projectIds: actor.projectIds,
        }),
        readCollaborationLimits(organization.id, workspaceId),
      ]);
      const dataLifecycle = await listDataLifecycleState({
        organizationId: organization.id,
        workspaceId,
        actor,
        readings: usage.readings,
        now,
      });
      return (
        <div className="space-y-5">
          <UsageView
            readings={usage.readings}
            projectedCost={usage.projectedMonthlyCost}
            zeroMode={workspace.zeroMode}
            measuredAt={usage.measuredAt}
            now={now}
            collaboration={collaboration}
          />
          <CapacityView initialState={dataLifecycle} now={now} />
        </div>
      );
    }

    case 'shield': {
      const state = await readShieldState(workspaceId);
      return (
        <ShieldView
          data={{
            score: state.scan?.score ?? null,
            grade: state.scan?.grade ?? null,
            headline: state.scan?.headline ?? null,
            scannedAt: state.scan?.createdAt ?? null,
            checks: state.checks,
            findings: state.findings,
            now,
          }}
        />
      );
    }

    case 'members': {
      const [members, projects] = await Promise.all([
        listMembers(organization.id, workspaceId),
        listProjects(workspaceId),
      ]);
      return <MembersView organization={organization} workspaceId={workspaceId} actor={actor} initialMembers={members} projects={projects} now={now} />;
    }

    case 'invitations':
      return <InvitationsView initialInvitations={await listInvitations(organization.id)} />;

    case 'service-accounts': {
      const [accounts, projects] = await Promise.all([
        listServiceAccounts(organization.id, workspaceId),
        listProjects(workspaceId),
      ]);
      return <ServiceAccountsView initialAccounts={accounts} projects={projects} />;
    }

    case 'audit':
      return <AuditView events={await listAuditEvents(organization.id)} now={now} />;

    case 'sessions':
      return <SessionsView initialSessions={await listOwnSessions(userId)} />;

    case 'settings':
      return (
        <SettingsView
          workspace={workspace}
          integrations={getIntegrationCatalog(runtimeEnv)}
        />
      );

    default:
      return <PreviewSection section={section} />;
  }
}
