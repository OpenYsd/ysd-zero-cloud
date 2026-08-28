import { notFound } from 'next/navigation';
import { isSection, SectionDashboard } from '@/components/section-dashboard';

export default async function SectionPage({ params }: { params: Promise<{ section: string }> }) {
  const { section } = await params;
  if (!isSection(section)) notFound();
  return <SectionDashboard section={section} />;
}
