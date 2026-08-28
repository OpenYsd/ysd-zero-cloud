'use client';

import Link from 'next/link';
import { useMemo, useState } from 'react';
import { Braces, CheckCircle2, ChevronRight, Clock3, Database, Play, Plus, RefreshCcw, Search, Table2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { cn } from '@/lib/utils';

const tableData = {
  users: {
    count: 1248,
    columns: ['id', 'name', 'email', 'plan', 'created_at'],
    rows: [
      ['usr_8F2A', 'Maha Alqahtani', 'maha@example.com', 'pro', '2026-08-27 18:21'],
      ['usr_19BC', 'Omar Hassan', 'omar@example.com', 'free', '2026-08-27 17:04'],
      ['usr_7D13', 'Lina Nasser', 'lina@example.com', 'developer', '2026-08-26 09:38'],
      ['usr_A2E8', 'Yousef Ali', 'yousef@example.com', 'free', '2026-08-25 22:11'],
    ],
  },
  projects: {
    count: 86,
    columns: ['id', 'name', 'owner', 'status', 'region'],
    rows: [
      ['prj_01H8', 'ysd-platform', 'usr_8F2A', 'active', 'global'],
      ['prj_01H9', 'shield-api', 'usr_19BC', 'active', 'riyadh'],
      ['prj_01HA', 'playground', 'usr_7D13', 'building', 'frankfurt'],
    ],
  },
  deployments: {
    count: 412,
    columns: ['id', 'project', 'commit', 'state', 'duration'],
    rows: [
      ['dpl_6C44', 'ysd-platform', '8f3c4a1', 'ready', '42s'],
      ['dpl_6C43', 'shield-api', '17ad31c', 'ready', '19s'],
      ['dpl_6C42', 'playground', 'a009d82', 'building', '—'],
    ],
  },
  audit_events: {
    count: 9840,
    columns: ['id', 'actor', 'action', 'resource', 'time'],
    rows: [
      ['evt_021C', 'usr_8F2A', 'project.deploy', 'prj_01H8', '18:24:11'],
      ['evt_021B', 'system', 'shield.scan', 'prj_01H9', '18:21:03'],
      ['evt_021A', 'usr_19BC', 'secret.rotate', 'sec_C18A', '17:52:40'],
    ],
  },
} as const;

type TableName = keyof typeof tableData;

export function DatabaseWorkspace({ mode }: { mode: 'studio' | 'sql-editor' }) {
  const [activeTable, setActiveTable] = useState<TableName>('users');
  const [query, setQuery] = useState('SELECT id, name, email, plan\nFROM users\nORDER BY created_at DESC\nLIMIT 50;');
  const [executedQuery, setExecutedQuery] = useState(query);
  const [filter, setFilter] = useState('');
  const data = tableData[activeTable];
  const visibleRows = useMemo(
    () => data.rows.filter((row) => row.some((cell) => cell.toLowerCase().includes(filter.toLowerCase()))),
    [data, filter],
  );

  return (
    <div className="mx-auto w-full max-w-[1440px] space-y-5">
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
        <div>
          <div className="mb-2 flex items-center gap-1.5 text-[10px] text-white/27"><Link href="/databases" className="hover:text-white/60">Databases</Link><ChevronRight className="size-3" /> primary-postgres</div>
          <h1 className="text-2xl font-semibold tracking-[-0.035em] text-white">{mode === 'studio' ? 'Database Studio' : 'SQL Editor'}</h1>
          <p className="mt-1 text-xs text-white/34">Explore and query the mock PostgreSQL workspace.</p>
        </div>
        <div className="flex items-center rounded-lg border border-white/[0.07] bg-white/[0.025] p-0.5">
          <Link href="/databases/studio" className={cn('rounded-md px-3 py-1.5 text-[11px] font-medium', mode === 'studio' ? 'bg-white/[0.08] text-white' : 'text-white/35')}><Table2 className="mr-1.5 inline size-3" />Studio</Link>
          <Link href="/databases/sql-editor" className={cn('rounded-md px-3 py-1.5 text-[11px] font-medium', mode === 'sql-editor' ? 'bg-white/[0.08] text-white' : 'text-white/35')}><Braces className="mr-1.5 inline size-3" />SQL Editor</Link>
        </div>
      </div>

      <div className="cloud-card grid min-h-[620px] overflow-hidden lg:grid-cols-[210px_minmax(0,1fr)]">
        <aside className="border-b border-white/[0.065] bg-black/10 p-3 lg:border-b-0 lg:border-r">
          <div className="mb-3 flex items-center justify-between px-2 py-1">
            <div className="flex items-center gap-2 text-[11px] font-semibold text-white/55"><Database className="size-3.5 text-[#7569ff]" /> Tables</div>
            <Button variant="ghost" size="icon-xs" aria-label="Create table"><Plus /></Button>
          </div>
          <div className="space-y-0.5">
            {(Object.keys(tableData) as TableName[]).map((table) => (
              <button key={table} onClick={() => setActiveTable(table)} className={cn('flex w-full items-center justify-between rounded-md px-2.5 py-2 text-left text-[11px] transition-colors', activeTable === table ? 'bg-[#7569ff]/10 text-[#b0aaff]' : 'text-white/36 hover:bg-white/[0.04] hover:text-white/65')}>
                <span className="flex items-center gap-2"><Table2 className="size-3" /> {table}</span><span className="font-mono text-[9px] opacity-45">{tableData[table].count}</span>
              </button>
            ))}
          </div>
        </aside>

        {mode === 'studio' ? (
          <div className="min-w-0">
            <div className="flex flex-col justify-between gap-3 border-b border-white/[0.065] px-4 py-3 sm:flex-row sm:items-center">
              <div><p className="text-xs font-semibold text-white/75">public.{activeTable}</p><p className="mt-0.5 text-[10px] text-white/25">{data.count.toLocaleString()} rows · Row Level Security on</p></div>
              <div className="flex gap-2">
                <div className="relative"><Search className="absolute left-2.5 top-1/2 size-3 -translate-y-1/2 text-white/25" /><Input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter rows" className="h-7 w-40 border-white/[0.07] bg-black/10 pl-7 text-[10px]" /></div>
                <Button variant="outline" size="sm" className="border-white/[0.07] bg-transparent text-[10px]"><RefreshCcw /> Refresh</Button>
                <Button size="sm" className="bg-[#7569ff] text-[10px] text-white"><Plus /> Insert row</Button>
              </div>
            </div>
            <DataGrid columns={data.columns} rows={visibleRows} />
          </div>
        ) : (
          <div className="grid min-w-0 grid-rows-[auto_minmax(230px,.8fr)_auto_minmax(190px,1fr)]">
            <div className="flex items-center justify-between border-b border-white/[0.065] px-4 py-2.5">
              <div className="flex items-center gap-2 text-[10px] text-white/35"><span className="size-1.5 rounded-full bg-[#b7ff3c]" /> primary-postgres</div>
              <Button onClick={() => setExecutedQuery(query)} size="sm" className="bg-[#b7ff3c] text-[10px] font-semibold text-[#07100c] hover:bg-[#cbff72]"><Play /> Run query</Button>
            </div>
            <div className="relative bg-[#0b100e]">
              <div className="pointer-events-none absolute inset-y-0 left-0 w-10 border-r border-white/[0.05] bg-black/10 pt-4 text-center font-mono text-[11px] leading-6 text-white/15">1<br />2<br />3<br />4</div>
              <Textarea value={query} onChange={(event) => setQuery(event.target.value)} spellCheck={false} className="h-full min-h-[230px] resize-none rounded-none border-0 bg-transparent py-4 pl-14 font-mono text-xs leading-6 text-[#d6ff92] focus-visible:ring-0" />
            </div>
            <div className="flex items-center justify-between border-y border-white/[0.065] px-4 py-2 text-[10px] text-white/28">
              <span>Results · {executedQuery ? '4 rows' : 'Not run'}</span><span className="flex items-center gap-1"><CheckCircle2 className="size-3 text-[#b7ff3c]" /> Success · <Clock3 className="ml-1 size-3" /> 18 ms</span>
            </div>
            <DataGrid columns={tableData.users.columns} rows={tableData.users.rows} />
          </div>
        )}
      </div>
    </div>
  );
}

function DataGrid({ columns, rows }: { columns: readonly string[]; rows: readonly (readonly string[])[] }) {
  return (
    <Table className="font-mono text-[10px]">
      <TableHeader><TableRow className="border-white/[0.065] hover:bg-transparent">{columns.map((column) => <TableHead key={column} className="h-9 border-r border-white/[0.04] px-3 text-[9px] uppercase tracking-[0.1em] text-white/24">{column}</TableHead>)}</TableRow></TableHeader>
      <TableBody>{rows.map((row, index) => <TableRow key={`${row[0]}-${index}`} className="border-white/[0.05] hover:bg-white/[0.025]">{row.map((cell, cellIndex) => <TableCell key={`${cell}-${cellIndex}`} className={cn('border-r border-white/[0.04] px-3 py-3 text-white/50', cellIndex === 0 && 'text-[#9f97ff]')}>{cell}</TableCell>)}</TableRow>)}</TableBody>
    </Table>
  );
}
