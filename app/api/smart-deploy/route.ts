import { createSmartDeployPlan, type DeployTarget } from '@/lib/smart-deploy';

export async function POST(request: Request) {
  const body = (await request.json()) as {
    repository?: string;
    target?: DeployTarget;
    zeroMode?: boolean;
  };

  if (!body.repository?.trim()) {
    return Response.json({ error: 'repository is required' }, { status: 400 });
  }

  const plan = createSmartDeployPlan(
    body.repository.trim(),
    body.target ?? 'auto',
    body.zeroMode ?? true,
  );

  return Response.json(plan, { status: plan.protection.allowed ? 200 : 403 });
}
