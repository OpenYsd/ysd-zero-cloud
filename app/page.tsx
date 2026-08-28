import { HomeDashboard } from '@/components/home-dashboard';
import { requestTime } from '@/lib/server/clock';
import { countDeployments } from '@/lib/server/deployments';
import { listProjects } from '@/lib/server/projects';
import { requireSession } from '@/lib/server/session';
import { readShieldState } from '@/lib/server/shield-scan';
import { summarizeUsage } from '@/lib/server/usage';

export default async function HomePage() {
  const { workspace } = await requireSession();

  const [projects, deploymentCount, usage, shield, now] = await Promise.all([
    listProjects(workspace.id),
    countDeployments(workspace.id),
    summarizeUsage(workspace.id),
    readShieldState(workspace.id),
    requestTime(),
  ]);

  return (
    <HomeDashboard
      data={{
        operator: workspace.name,
        projects,
        projectCount: projects.length,
        deploymentCount,
        tableCount: usage.tableCount,
        readings: usage.readings,
        projectedMonthlyCost: usage.projectedMonthlyCost,
        shieldScore: shield.scan?.score ?? null,
        zeroMode: workspace.zeroMode,
        now,
      }}
    />
  );
}

export const metadata = { title: 'Overview' };

// Every figure is read per request; nothing here is safe to pre-render.
export const dynamic = 'force-dynamic';
