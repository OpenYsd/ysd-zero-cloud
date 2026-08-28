'use client';

import Link from 'next/link';
import { useEffect, useState, useTransition } from 'react';
import {
  AlertTriangle,
  Braces,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Clock3,
  Database,
  EyeOff,
  Loader2,
  Play,
  RefreshCcw,
  Search,
  ShieldCheck,
  Table2,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import type { TablePage, TableSummary } from '@/lib/domain';
import { cn } from '@/lib/utils';
import type { SqlAnalysis } from '@/lib/sql-guard';

/**
 * Database Studio and the SQL Editor.
 *
 * Both read the real D1 database through `/api/database/*`. Credential columns
 * arrive already masked from the server, and the editor renders the guard's
 * refusal verbatim rather than reinterpreting it.
 */

const PAGE_SIZE = 50;

type QueryResponse = {
  analysis: SqlAnalysis;
  columns: string[];
  rows: Record<string, unknown>[];
  rowsRead: number;
  rowsWritten: number;
  durationMs: number;
  truncated: boolean;
  error?: string;
};

export function DatabaseWorkspace({
  mode,
  tables,
  initialTable,
  canUseSqlEditor,
}: {
  mode: 'studio' | 'sql-editor';
  tables: TableSummary[];
  initialTable: string | null;
  /** False for anyone but the instance owner; see the query route for why. */
  canUseSqlEditor: boolean;
}) {
  const [activeTable, setActiveTable] = useState(initialTable);

  return (
    <div className="mx-auto w-full max-w-[1440px] space-y-5">
      <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
        <div>
          <div className="mb-2 flex items-center gap-1.5 text-[10px] text-white/27">
            <Link href="/databases" className="hover:text-white/60">Databases</Link>
            <ChevronRight className="size-3" /> ysd-zero-cloud · D1
          </div>
          <h1 className="text-2xl font-semibold tracking-[-0.035em] text-white">
            {mode === 'studio' ? 'Database Studio' : 'SQL Editor'}
          </h1>
          <p className="mt-1 text-xs text-white/34">
            {mode === 'studio'
              ? 'Browse the live database. Credential columns are redacted before they leave the server.'
              : 'Run one statement at a time against D1, checked by the SQL guard first.'}
          </p>
        </div>
        <div className="flex items-center rounded-lg border border-white/[0.07] bg-white/[0.025] p-0.5">
          <Link
            href="/databases/studio"
            className={cn('rounded-md px-3 py-1.5 text-[11px] font-medium', mode === 'studio' ? 'bg-white/[0.08] text-white' : 'text-white/35')}
          >
            <Table2 className="mr-1.5 inline size-3" />Studio
          </Link>
          <Link
            href="/databases/sql-editor"
            className={cn('rounded-md px-3 py-1.5 text-[11px] font-medium', mode === 'sql-editor' ? 'bg-white/[0.08] text-white' : 'text-white/35')}
          >
            <Braces className="mr-1.5 inline size-3" />SQL Editor
          </Link>
        </div>
      </div>

      <div className="cloud-card grid min-h-[620px] overflow-hidden lg:grid-cols-[230px_minmax(0,1fr)]">
        <aside className="border-b border-white/[0.065] bg-black/10 p-3 lg:border-b-0 lg:border-r">
          <div className="mb-3 flex items-center justify-between px-2 py-1">
            <div className="flex items-center gap-2 text-[11px] font-semibold text-white/55">
              <Database className="size-3.5 text-[#7569ff]" /> Tables
            </div>
            <span className="font-mono text-[9px] text-white/25">{tables.length}</span>
          </div>
          <div className="space-y-0.5">
            {tables.map((table) => (
              <button
                key={table.name}
                type="button"
                onClick={() => setActiveTable(table.name)}
                className={cn(
                  'flex w-full items-center justify-between gap-2 rounded-md px-2.5 py-2 text-left text-[11px] transition-colors',
                  activeTable === table.name
                    ? 'bg-[#7569ff]/10 text-[#b0aaff]'
                    : 'text-white/36 hover:bg-white/[0.04] hover:text-white/65',
                )}
              >
                <span className="flex min-w-0 items-center gap-2">
                  <Table2 className="size-3 shrink-0" />
                  <span className="truncate font-mono">{table.name}</span>
                  {table.masked && <EyeOff className="size-2.5 shrink-0 text-amber-300/60" />}
                </span>
                <span className="font-mono text-[9px] opacity-45">{table.rows}</span>
              </button>
            ))}
          </div>
        </aside>

        {mode === 'studio' ? (
          <StudioGrid key={activeTable} table={activeTable} />
        ) : canUseSqlEditor ? (
          <SqlEditor />
        ) : (
          <div className="grid place-items-center p-10 text-center">
            <div className="max-w-sm">
              <span className="mx-auto grid size-10 place-items-center rounded-full border border-white/[0.08] bg-white/[0.025] text-white/35">
                <ShieldCheck className="size-4" />
              </span>
              <p className="mt-4 text-xs font-semibold text-white/60">
                The SQL Editor is limited to the instance owner
              </p>
              <p className="mt-2 text-[11px] leading-5 text-white/30">
                Every workspace shares one database, and a raw statement cannot be scoped to yours.
                Database Studio shows the same tables limited to your own rows.
              </p>
              <Link
                href="/databases/studio"
                className="mt-4 inline-block rounded-md bg-[#b7ff3c] px-3 py-1.5 text-[11px] font-semibold text-[#07100c]"
              >
                Open Database Studio
              </Link>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * One page of a table.
 *
 * The parent keys this component by table name, so switching tables remounts
 * it and the offset resets without an effect having to reach in and clear it.
 */
function StudioGrid({ table }: { table: string | null }) {
  const [page, setPage] = useState<TablePage | null>(null);
  const [filter, setFilter] = useState('');
  const [offset, setOffset] = useState(0);
  const [refreshKey, setRefreshKey] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [loading, startLoading] = useTransition();

  useEffect(() => {
    if (!table) return;
    const controller = new AbortController();

    startLoading(async () => {
      const params = new URLSearchParams({
        table,
        limit: String(PAGE_SIZE),
        offset: String(offset),
      });
      if (filter.trim()) params.set('filter', filter.trim());

      try {
        const response = await fetch(`/api/database/rows?${params.toString()}`, {
          signal: controller.signal,
        });
        const body = (await response.json()) as TablePage & { error?: string };
        if (!response.ok) throw new Error(body.error ?? 'The table could not be read.');
        setPage(body);
        setError(null);
      } catch (cause) {
        if (controller.signal.aborted) return;
        setPage(null);
        setError(cause instanceof Error ? cause.message : 'The table could not be read.');
      }
    });

    return () => controller.abort();
  }, [table, offset, filter, refreshKey]);

  if (!table) {
    return <div className="grid place-items-center p-10 text-[11px] text-white/28">Select a table to browse.</div>;
  }

  return (
    <div className="min-w-0">
      <div className="flex flex-col justify-between gap-3 border-b border-white/[0.065] px-4 py-3 sm:flex-row sm:items-center">
        <div>
          <p className="font-mono text-xs font-semibold text-white/75">{table}</p>
          <p className="mt-0.5 text-[10px] text-white/25">
            {page ? `${page.total.toLocaleString('en-US')} rows` : 'Loading…'}
            {page && page.maskedColumns.length > 0 && (
              <span className="ml-2 text-amber-300/60">
                {page.maskedColumns.length} column{page.maskedColumns.length === 1 ? '' : 's'} redacted
              </span>
            )}
          </p>
        </div>
        <div className="flex gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 size-3 -translate-y-1/2 text-white/25" />
            <Input
              value={filter}
              onChange={(event) => {
                setFilter(event.target.value);
                setOffset(0);
              }}
              placeholder="Filter rows"
              aria-label="Filter rows"
              className="h-7 w-40 border-white/[0.07] bg-black/10 pl-7 text-[10px]"
            />
          </div>
          <Button
            variant="outline"
            size="sm"
            className="border-white/[0.07] bg-transparent text-[10px]"
            onClick={() => setRefreshKey((key) => key + 1)}
            disabled={loading}
          >
            {loading ? <Loader2 className="animate-spin" /> : <RefreshCcw />} Refresh
          </Button>
        </div>
      </div>

      {error ? (
        <p role="alert" className="p-6 text-[11px] text-red-300">{error}</p>
      ) : (
        <>
          <DataGrid
            columns={page?.columns.map((column) => column.name) ?? []}
            rows={page?.rows ?? []}
            maskedColumns={page?.maskedColumns ?? []}
          />
          {page && page.total > PAGE_SIZE && (
            <div className="flex items-center justify-between border-t border-white/[0.065] px-4 py-2.5 text-[10px] text-white/30">
              <span>
                {offset + 1}–{Math.min(offset + PAGE_SIZE, page.total)} of {page.total.toLocaleString('en-US')}
              </span>
              <div className="flex gap-1">
                <Button
                  variant="ghost"
                  size="icon-xs"
                  aria-label="Previous page"
                  disabled={offset === 0}
                  onClick={() => setOffset((value) => Math.max(0, value - PAGE_SIZE))}
                >
                  <ChevronLeft />
                </Button>
                <Button
                  variant="ghost"
                  size="icon-xs"
                  aria-label="Next page"
                  disabled={offset + PAGE_SIZE >= page.total}
                  onClick={() => setOffset((value) => value + PAGE_SIZE)}
                >
                  <ChevronRight />
                </Button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

const DEFAULT_QUERY = `SELECT name, framework, status, region
FROM project
ORDER BY updatedAt DESC;`;

function SqlEditor() {
  const [query, setQuery] = useState(DEFAULT_QUERY);
  const [allowWrite, setAllowWrite] = useState(false);
  const [result, setResult] = useState<QueryResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  async function run() {
    setRunning(true);
    setError(null);
    try {
      const response = await fetch('/api/database/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sql: query, allowWrite }),
      });
      const body = (await response.json()) as QueryResponse;
      // 422 carries the guard's verdict; only a missing analysis is a real error.
      if (!body.analysis) throw new Error(body.error ?? 'The statement could not be run.');
      setResult(body);
    } catch (cause) {
      setResult(null);
      setError(cause instanceof Error ? cause.message : 'The statement could not be run.');
    } finally {
      setRunning(false);
    }
  }

  const blocked = result && !result.analysis.allowed;

  return (
    <div className="grid min-w-0 grid-rows-[auto_minmax(220px,.8fr)_auto_minmax(190px,1fr)]">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.065] px-4 py-2.5">
        <div className="flex items-center gap-2 text-[10px] text-white/35">
          <span className="size-1.5 rounded-full bg-[#b7ff3c]" /> ysd-zero-cloud · D1
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-[10px] text-white/40">
            <Switch
              checked={allowWrite}
              onCheckedChange={setAllowWrite}
              aria-label="Allow writes"
              className="data-checked:bg-amber-400"
            />
            <span>Write mode</span>
          </div>
          <Button
            onClick={run}
            disabled={running || !query.trim()}
            size="sm"
            className="bg-[#b7ff3c] text-[10px] font-semibold text-[#07100c] hover:bg-[#cbff72]"
          >
            {running ? <Loader2 className="animate-spin" /> : <Play />} Run query
          </Button>
        </div>
      </div>

      <div className="relative bg-[#0b100e]">
        <Textarea
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          spellCheck={false}
          aria-label="SQL statement"
          className="h-full min-h-[220px] resize-none rounded-none border-0 bg-transparent p-4 font-mono text-xs leading-6 text-[#d6ff92] focus-visible:ring-0"
        />
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 border-y border-white/[0.065] px-4 py-2 text-[10px]">
        {error ? (
          <span role="alert" className="text-red-300">{error}</span>
        ) : blocked ? (
          <span className="flex items-center gap-1.5 text-amber-300">
            <AlertTriangle className="size-3" /> {result.analysis.reason}
          </span>
        ) : result ? (
          <>
            <span className="text-white/28">
              {result.analysis.kind === 'write'
                ? `${result.rowsWritten} row${result.rowsWritten === 1 ? '' : 's'} written`
                : `${result.rows.length} row${result.rows.length === 1 ? '' : 's'}${result.truncated ? ' (capped)' : ''}`}
            </span>
            <span className="flex items-center gap-1 text-white/28">
              <CheckCircle2 className="size-3 text-[#b7ff3c]" /> {result.analysis.verb}
              <Clock3 className="ml-1 size-3" /> {result.durationMs} ms
              <Badge variant="outline" className="ml-2 border-white/[0.09] text-[9px] text-white/40">
                {result.analysis.kind}
              </Badge>
            </span>
          </>
        ) : (
          <span className="flex items-center gap-1.5 text-white/28">
            <ShieldCheck className="size-3 text-[#b7ff3c]/60" />
            Reads run by default. Credential tables are unreachable from here.
          </span>
        )}
      </div>

      {result?.analysis.allowed ? (
        <DataGrid columns={result.columns} rows={result.rows} maskedColumns={[]} />
      ) : (
        <div className="grid place-items-center p-8 text-center text-[11px] text-white/25">
          {blocked
            ? 'Adjust the statement and run it again.'
            : 'Results appear here once a statement runs.'}
        </div>
      )}
    </div>
  );
}

function renderCell(value: unknown): string {
  if (value === null || value === undefined) return 'NULL';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return value.toString();
  }
  // D1 can hand back a BLOB as an array, and JSON columns arrive as objects.
  return JSON.stringify(value) ?? '';
}

function DataGrid({
  columns,
  rows,
  maskedColumns,
}: {
  columns: string[];
  rows: Record<string, unknown>[];
  maskedColumns: string[];
}) {
  if (columns.length === 0) {
    return <div className="grid place-items-center p-8 text-[11px] text-white/25">No columns to show.</div>;
  }

  return (
    <div className="overflow-x-auto">
      <Table className="font-mono text-[10px]">
        <TableHeader>
          <TableRow className="border-white/[0.065] hover:bg-transparent">
            {columns.map((column) => (
              <TableHead
                key={column}
                className="h-9 whitespace-nowrap border-r border-white/[0.04] px-3 text-[9px] uppercase tracking-[0.1em] text-white/24"
              >
                {column}
                {maskedColumns.includes(column) && <EyeOff className="ml-1 inline size-2.5 text-amber-300/60" />}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.length === 0 ? (
            <TableRow className="hover:bg-transparent">
              <TableCell colSpan={columns.length} className="px-3 py-8 text-center text-white/25">
                No rows.
              </TableCell>
            </TableRow>
          ) : (
            rows.map((row, index) => (
              <TableRow key={index} className="border-white/[0.05] hover:bg-white/[0.025]">
                {columns.map((column, cellIndex) => (
                  <TableCell
                    key={column}
                    className={cn(
                      'max-w-[280px] truncate border-r border-white/[0.04] px-3 py-3 text-white/50',
                      cellIndex === 0 && 'text-[#9f97ff]',
                    )}
                    title={renderCell(row[column])}
                  >
                    {renderCell(row[column])}
                  </TableCell>
                ))}
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  );
}
