import type { Metadata } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import { CloudShell } from '@/components/cloud-shell';
import './globals.css';

const geistSans = Geist({ variable: '--font-geist-sans', subsets: ['latin'] });
const geistMono = Geist_Mono({ variable: '--font-geist-mono', subsets: ['latin'] });

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL ?? 'http://localhost:3000'),
  title: { default: 'YSD Zero Cloud', template: '%s · YSD Zero Cloud' },
  description:
    'A zero-cost-first cloud operating system for projects, data, AI, and game infrastructure.',
  openGraph: {
    title: 'YSD Zero Cloud',
    description: 'Cloud OS. Zero surprise costs.',
    images: [{ url: '/og.png', width: 1200, height: 630, alt: 'YSD Zero Cloud' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'YSD Zero Cloud',
    description: 'Cloud OS. Zero surprise costs.',
    images: ['/og.png'],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="dark">
      <body className={`${geistSans.variable} ${geistMono.variable} antialiased`}>
        <CloudShell>{children}</CloudShell>
      </body>
    </html>
  );
}
