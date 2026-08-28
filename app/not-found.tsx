import Link from 'next/link';
import { CloudOff, Home } from 'lucide-react';
import { Button } from '@/components/ui/button';

export default function NotFound() {
  return (
    <div className="grid min-h-[65vh] place-items-center text-center">
      <div>
        <span className="mx-auto grid size-12 place-items-center rounded-full border border-white/[0.08] bg-white/[0.03] text-white/35"><CloudOff /></span>
        <h1 className="mt-5 text-xl font-semibold text-white">Resource not found</h1>
        <p className="mt-2 text-xs text-white/32">This cloud surface does not exist in the v0.1 workspace.</p>
        <Button nativeButton={false} className="mt-5 bg-[#b7ff3c] text-xs font-semibold text-[#07100c]" render={<Link href="/" />}><Home /> Back home</Button>
      </div>
    </div>
  );
}
