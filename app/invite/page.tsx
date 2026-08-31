import { InvitationAcceptance } from '@/components/collaboration-views';
import { requireSession } from '@/lib/server/session';

export const dynamic = 'force-dynamic';
export const metadata = { title: 'Accept invitation' };

export default async function InvitePage() {
  await requireSession();
  return <InvitationAcceptance />;
}
