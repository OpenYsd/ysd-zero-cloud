'use client';

import { useEffect, useState, useTransition } from 'react';
import { Loader2, Pause, Play, RefreshCcw, Search } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { NativeSelect } from '@/components/ui/native-select';
import { LOG_LEVELS, LOG_SOURCES, type LogEvent } from '@/lib/domain';
import { logTime } from '@/lib/format';

/**
 * The workspace log stream.
 *
 * Live tail is a poll rather than a socket: a Worker holding an open
 * connection would burn the request budget the whole workspace runs on, and a
 * five-second refresh is indistinguishable for an audit feed.
 */

const POLL_MS = 5000;

const LEVEL_TONE: Record<LogEvent['level'], string> = {
  INFO: 'text-[#b7ff3c]/60',
  WARN: 'text-amber-300/75',
  ERROR: 'text-red-300/80',
};

export function LogsView({ initialEvents }: { initialEvents: LogEvent[] }) {
  const [events, setEvents] = useState(initialEvents);
  const [search, setSearch] = useState('');
  const [source, setSource] = useState('');
  const [level, setLevel] = useState('');
  const [live, setLive] = useState(true);
  // Bumped to ask for a fetch without changing any filter.
  const [refreshKey, setRefreshKey] = useState(0);
  const [loading, startLoading] = useTransition();

  useEffect(() => {
    const controller = new AbortController();

    startLoading(async () => {
      const params = new URLSearchParams();
      if (search.trim()) params.set('search', search.trim());
      if (source) params.set('source', source);
      if (level) params.set('level', level);

      try {
        const response = await fetch(`/api/logs?${params.toString()}`, {
          signal: controller.signal,
        });
        if (!response.ok) return;
        const body = (await response.json()) as { events: LogEvent[] };
        setEvents(body.events);
      } catch {
        // Aborted by a newer filter, or the network dropped. The previous
        // page of events stays on screen rather than blanking.
      }
    });

    // Cancelling in the cleanup means a slow response from an earlier filter
    // can never overwrite the results of a newer one.
    return () => controller.abort();
  }, [search, source, level, refreshKey]);

  useEffect(() => {
    if (!live) return;
    const timer = setInterval(() => setRefreshKey((key) => key + 1), POLL_MS);
    return () => clearInterval(timer);
  }, [live]);

  return (
    <div className="cloud-card overflow-hidden">
      <div className="flex flex-col justify-between gap-3 border-b border-white/[0.065] p-4 sm:flex-row sm:items-center">
        <div className="flex flex-wrap gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 size-3 -translate-y-1/2 text-white/25" />
            <Input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search messages"
              aria-label="Search logs"
              className="h-8 w-56 border-white/[0.07] bg-black/10 pl-7 text-[10px]"
            />
          </div>
          <NativeSelect
            value={source}
            onChange={(event) => setSource(event.target.value)}
            aria-label="Filter by source"
            className="h-8 border-white/[0.07] bg-black/10 text-[10px]"
          >
            <option value="">All sources</option>
            {LOG_SOURCES.map((option) => (
              <option key={option} value={option}>{option}</option>
            ))}
          </NativeSelect>
          <NativeSelect
            value={level}
            onChange={(event) => setLevel(event.target.value)}
            aria-label="Filter by level"
            className="h-8 border-white/[0.07] bg-black/10 text-[10px]"
          >
            <option value="">All levels</option>
            {LOG_LEVELS.map((option) => (
              <option key={option} value={option}>{option}</option>
            ))}
          </NativeSelect>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="border-white/[0.07] text-[10px]"
            onClick={() => setRefreshKey((key) => key + 1)}
            disabled={loading}
          >
            {loading ? <Loader2 className="animate-spin" /> : <RefreshCcw />} Refresh
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className={live ? 'text-[10px] text-[#c8ff69]' : 'text-[10px] text-white/40'}
            onClick={() => setLive((state) => !state)}
          >
            {live ? <Pause /> : <Play />}
            {live ? 'Live tail' : 'Paused'}
          </Button>
        </div>
      </div>

      <div className="min-h-[520px] bg-[#080c0a] p-4 font-mono text-[11px] leading-7">
        {events.length === 0 ? (
          <p className="py-16 text-center text-white/28">
            No events match this filter. Actions you take in the workspace appear here.
          </p>
        ) : (
          events.map((event) => (
            <div
              key={event.id}
              className="grid grid-cols-[104px_52px_88px_minmax(0,1fr)] gap-2 border-b border-white/[0.035]"
            >
              <span className="text-white/18">{logTime(event.createdAt)}</span>
              <span className={LEVEL_TONE[event.level]}>{event.level}</span>
              <span className="truncate text-[#9f97ff]/65">{event.source}</span>
              <span className="truncate text-white/48" title={event.message}>
                {event.message}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
