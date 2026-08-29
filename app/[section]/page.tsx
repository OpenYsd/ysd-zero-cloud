import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { AdminView } from '@/components/admin-view';
import { LogsView } from '@/components/logs-view';
import { NetworkingView } from '@/components/networking-view';
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
import { PageHeader } from '@/components/ui-bits';
import type { Workspace } from '@/lib/domain';
import type { Actor } from '@/lib/roles';
import { FREE_TIER_LIMITS } from '@/lib/free-tier';
import { getIntegrationCatalog } from '@/lib/integrations';
import { can } from '@/lib/roles';
import { requestTime } from '@/lib/server/clock';
import { countOwners, listManagedUsers } from '@/lib/server/roles';
import { listDeployments } from '@/lib/server/deployments';
import { runtimeEnv } from '@/lib/server/env';
import { listLogs } from '@/lib/server/logs';
import { readNetworkState } from '@/lib/server/networking';
import { listProjects } from '@/lib/server/projects';
import { listSecrets } from '@/lib/server/secrets';
import { requireSession } from '@/lib/server/session';
import { readShieldState } from '@/lib/server/shield-scan';
import { databaseBytes, listTables } from '@/lib/server/studio';
import { listStorage } from '@/lib/server/storage';
import { summarizeUsage } from '@/lib/server/usage';

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
}: {
  params: Promise<{ section: string }>;
}) {
  const { section } = await params;
  if (!isSection(section)) notFound();

  const { workspace, actor } = await requireSession();

  // The admin surface is not merely hidden from the navigation: reaching it
  // directly without the capability sends the visitor back to the overview.
  if (section === 'admin' && !can(actor, 'admin.users.read')) notFound();

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
        actor={actor}
        now={now}
      />
    </div>
  );
}

async function SectionBody({
  section,
  workspace,
  actor,
  now,
}: {
  section: Section;
  workspace: Workspace;
  actor: Actor;
  now: number;
}) {
  const workspaceId = workspace.id;

  switch (section) {
    case 'projects':
      return (
        <ProjectsView projects={await listProjects(workspaceId)} now={now} />
      );

    case 'deployments':
      return (
        <>
          <SmartDeployPanel />
          <DeploymentsList
            deployments={await listDeployments(workspaceId)}
            now={now}
          />
        </>
      );

    case 'databases': {
      const [tables, bytes] = await Promise.all([
        listTables({ workspaceId, userId: workspace.ownerUserId }),
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
        <LogsView initialEvents={await listLogs(workspaceId, { limit: 100 })} />
      );

    case 'storage':
      return <StorageView state={await listStorage(workspaceId)} now={now} />;

    case 'networking':
      return <NetworkingView state={readNetworkState()} />;

    case 'secrets':
      return <SecretsView secrets={await listSecrets(workspaceId)} now={now} />;

    case 'usage': {
      const usage = await summarizeUsage(workspaceId, workspace.ownerUserId);
      return (
        <UsageView
          readings={usage.readings}
          projectedCost={usage.projectedMonthlyCost}
          zeroMode={workspace.zeroMode}
          measuredAt={usage.measuredAt}
          now={now}
        />
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

    case 'admin': {
      const [users, ownerCount] = await Promise.all([
        listManagedUsers(),
        countOwners(),
      ]);
      return (
        <AdminView
          users={users}
          actor={actor}
          ownerCount={ownerCount}
          now={now}
        />
      );
    }

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
