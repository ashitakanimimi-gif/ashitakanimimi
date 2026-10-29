import React, { createContext, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type {
  GraphQLRequest,
  ScanResult,
  ScanSummary,
  TestResult,
  HostGeo,
  Recommendation,
} from "@shared/types.js";
import { startScan } from "./api.js";

export interface ScanOptions {
  secondAuthHeader?: string;
  objectIdField?: string;
  objectIdValue?: string;
  callbackHost?: string;
  enableBruteForce?: boolean;
  enableInjection?: boolean;
  enableWordlist?: boolean;
}

interface Progress {
  done: number;
  total: number;
  current?: string;
}

interface AppState {
  base: GraphQLRequest | null;
  setBase: (b: GraphQLRequest | null) => void;
  acknowledged: boolean;
  setAcknowledged: (v: boolean) => void;
  options: ScanOptions;
  setOptions: (o: ScanOptions) => void;

  running: boolean;
  liveSummary: ScanSummary | null;
  liveResults: TestResult[];
  liveHosts: HostGeo[];
  progress: Progress;
  scan: (ScanResult & { recommendations?: Recommendation[] }) | null;
  history: ScanResult[];
  error: string | null;

  run: (selectedTestIds?: string[]) => Promise<void>;
  abort: () => void;
  loadHistory: (s: ScanResult) => void;
}

const Ctx = createContext<AppState | null>(null);

const LS_BASE = "gqlsec.base";
const LS_HISTORY = "gqlsec.history";

function load<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return v ? (JSON.parse(v) as T) : fallback;
  } catch {
    return fallback;
  }
}

export function AppProvider({ children }: { children: ReactNode }) {
  const [base, setBaseState] = useState<GraphQLRequest | null>(() => load<GraphQLRequest | null>(LS_BASE, null));
  const [acknowledged, setAcknowledged] = useState(false);
  const [options, setOptions] = useState<ScanOptions>({ enableInjection: true });

  const [running, setRunning] = useState(false);
  const [liveSummary, setLiveSummary] = useState<ScanSummary | null>(null);
  const [liveResults, setLiveResults] = useState<TestResult[]>([]);
  const [liveHosts, setLiveHosts] = useState<HostGeo[]>([]);
  const [progress, setProgress] = useState<Progress>({ done: 0, total: 0 });
  const [scan, setScan] = useState<(ScanResult & { recommendations?: Recommendation[] }) | null>(null);
  const [history, setHistory] = useState<ScanResult[]>(() => load<ScanResult[]>(LS_HISTORY, []));
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const setBase = (b: GraphQLRequest | null) => {
    setBaseState(b);
    try {
      if (b) localStorage.setItem(LS_BASE, JSON.stringify(b));
    } catch {
      /* ignore */
    }
  };

  useEffect(() => {
    try {
      localStorage.setItem(LS_HISTORY, JSON.stringify(history.slice(-20)));
    } catch {
      /* ignore */
    }
  }, [history]);

  const run = async (selectedTestIds?: string[]) => {
    if (!base) {
      setError("Set a target request first (Target page).");
      return;
    }
    setError(null);
    setRunning(true);
    setScan(null);
    setLiveResults([]);
    setLiveHosts([]);
    setLiveSummary(null);
    setProgress({ done: 0, total: selectedTestIds?.length ?? 0 });

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      await startScan(
        { base, acknowledged: true, selectedTestIds, options },
        (e) => {
          if (e.type === "start") setProgress({ done: 0, total: e.total });
          else if (e.type === "test-start") setProgress((p) => ({ ...p, current: e.title }));
          else if (e.type === "test-result") {
            setLiveResults((r) => [...r, e.result]);
            setLiveSummary(e.summary);
            setProgress((p) => ({ ...p, done: p.done + 1 }));
          } else if (e.type === "host") {
            setLiveHosts((h) => [...h, e.host]);
          } else if (e.type === "done") {
            setScan(e.scan as any);
            setLiveSummary(e.scan.summary);
            setHistory((h) => [...h, e.scan]);
          } else if (e.type === "error") {
            setError(e.message);
          }
        },
        controller.signal
      );
    } catch (err) {
      if ((err as Error).name !== "AbortError") setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRunning(false);
      abortRef.current = null;
    }
  };

  const abort = () => {
    abortRef.current?.abort();
    setRunning(false);
  };

  const loadHistory = (s: ScanResult) => {
    setScan(s as any);
    setLiveSummary(s.summary);
    setLiveResults(s.results);
    setLiveHosts(s.hosts);
  };

  const value = useMemo<AppState>(
    () => ({
      base,
      setBase,
      acknowledged,
      setAcknowledged,
      options,
      setOptions,
      running,
      liveSummary,
      liveResults,
      liveHosts,
      progress,
      scan,
      history,
      error,
      run,
      abort,
      loadHistory,
    }),
    [base, acknowledged, options, running, liveSummary, liveResults, liveHosts, progress, scan, history, error]
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useApp(): AppState {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useApp must be used within AppProvider");
  return ctx;
}
