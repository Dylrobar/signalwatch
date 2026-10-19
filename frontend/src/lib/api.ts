import type { R } from "./format";

export type ApiErrorKind = "disconnected" | "unauthorized" | "network" | "http" | "invalid" | "aborted";

export class ApiError extends Error {
  kind: ApiErrorKind;
  status: number | undefined;
  constructor(kind: ApiErrorKind, message: string, status?: number) {
    super(message);
    this.kind = kind;
    this.status = status;
  }
}

export type Connection = { baseUrl: string | null; token: string; remember: boolean; gen: number };

const URL_KEY = "signalwatch.baseUrl";
const TOKEN_KEY = "signalwatch.token";
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

let current: Connection = { baseUrl: null, token: "", remember: false, gen: 0 };
let controller: AbortController | null = null;
const listeners = new Set<() => void>();
const SERVER_SNAPSHOT: Connection = current;

function emit() {
  listeners.forEach((fn) => fn());
}

function rotate() {
  controller?.abort();
  controller = new AbortController();
}

export function normalizeBaseUrl(input: string): string {
  const raw = input.trim();
  if (!raw) throw new Error("Enter the backend base URL.");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("Enter a full URL including https://");
  }
  if (url.username || url.password) throw new Error("Do not include credentials in the URL; use the token field.");
  if (url.search || url.hash) throw new Error("The base URL cannot include a query string or fragment.");
  if (url.protocol === "http:") {
    if (!LOCAL_HOSTS.has(url.hostname)) throw new Error("Use HTTPS. Plain HTTP is only allowed for localhost development.");
  } else if (url.protocol !== "https:") {
    throw new Error("Only HTTPS (or HTTP for localhost) URLs are supported.");
  }
  return url.origin + url.pathname.replace(/\/+$/, "");
}

export function joinUrl(base: string, path: string, params?: URLSearchParams | Record<string, string>) {
  const query = params ? new URLSearchParams(params as Record<string, string>).toString() : "";
  return base.replace(/\/+$/, "") + "/" + path.replace(/^\/+/, "") + (query ? "?" + query : "");
}

export const connection = {
  get: () => current,
  getServer: () => SERVER_SNAPSHOT,
  subscribe(fn: () => void) {
    listeners.add(fn);
    return () => listeners.delete(fn);
  },
  hydrate() {
    if (typeof window === "undefined") return;
    let baseUrl: string | null = null;
    let token = "";
    try {
      const saved = window.localStorage.getItem(URL_KEY);
      baseUrl = saved ? normalizeBaseUrl(saved) : null;
      token = window.sessionStorage.getItem(TOKEN_KEY) ?? "";
    } catch {
      baseUrl = null;
    }
    if (baseUrl === current.baseUrl && token === current.token) return;
    rotate();
    current = { baseUrl, token, remember: Boolean(token), gen: current.gen + 1 };
    emit();
  },
  set(baseUrl: string, token: string, remember: boolean) {
    rotate();
    current = { baseUrl, token, remember: remember && Boolean(token), gen: current.gen + 1 };
    try {
      window.localStorage.setItem(URL_KEY, baseUrl);
      if (current.remember) window.sessionStorage.setItem(TOKEN_KEY, token);
      else window.sessionStorage.removeItem(TOKEN_KEY);
    } catch {}
    emit();
  },
  clear() {
    rotate();
    current = { baseUrl: null, token: "", remember: false, gen: current.gen + 1 };
    try {
      window.localStorage.removeItem(URL_KEY);
      window.sessionStorage.removeItem(TOKEN_KEY);
    } catch {}
    emit();
  },
};

export function describeDetail(body: unknown): string {
  if (body == null) return "";
  if (typeof body === "string") return body;
  if (Array.isArray(body)) return body.map(describeDetail).filter(Boolean).join("; ");
  if (typeof body === "object") {
    const o = body as Record<string, unknown>;
    if (o["detail"] !== undefined) return describeDetail(o["detail"]);
    if (o["msg"] !== undefined) return [Array.isArray(o["loc"]) ? o["loc"].join(".") : "", String(o["msg"])].filter(Boolean).join(": ");
    if (o["error"] !== undefined) return describeDetail(o["error"]);
    if (o["message"] !== undefined) return describeDetail(o["message"]);
    return JSON.stringify(body);
  }
  return String(body);
}

function linkSignals(signals: (AbortSignal | undefined)[]) {
  return AbortSignal.any(signals.filter((signal): signal is AbortSignal => signal !== undefined));
}

type Options = { method?: string; body?: unknown; rawBody?: BodyInit; contentType?: string; filename?: string; params?: Record<string, string>; signal?: AbortSignal };

async function send(base: string, token: string, path: string, opts: Options, global?: AbortSignal) {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const body = opts.rawBody ?? (opts.body !== undefined ? JSON.stringify(opts.body) : undefined);
  if (body !== undefined) headers["Content-Type"] = opts.contentType ?? "application/json";
  if (opts.filename) headers["X-Filename"] = encodeURIComponent(opts.filename);
  const signal = linkSignals([opts.signal, global]);
  let response: Response;
  try {
    response = await fetch(joinUrl(base, path, opts.params), { method: opts.method ?? "GET", headers, ...(body !== undefined ? { body } : {}), signal });
  } catch {
    if (signal.aborted) {
      if (signal.reason?.name === "TimeoutError") throw new ApiError("network", "The backend connection timed out.");
      throw new ApiError("aborted", "Request cancelled");
    }
    const origin = typeof window === "undefined" ? "this site" : window.location.origin;
    throw new ApiError(
      "network",
      `Could not reach the backend. It may be offline, the URL may be wrong, or SIGNALWATCH_CORS_ORIGINS may not include ${origin}.`,
    );
  }
  if (!response.ok) {
    let detail = "";
    try {
      const text = await response.text();
      try {
        detail = describeDetail(JSON.parse(text));
      } catch {
        detail = text.slice(0, 300);
      }
    } catch {
      detail = "";
    }
    const kind = response.status === 401 || response.status === 403 ? "unauthorized" : "http";
    throw new ApiError(kind, `HTTP ${response.status}${detail ? `: ${detail}` : ""}`, response.status);
  }
  return response;
}

async function json<T>(response: Response): Promise<T> {
  try {
    return (await response.json()) as T;
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw new ApiError("aborted", "Request cancelled");
    throw new ApiError("invalid", `HTTP ${response.status} returned a response that is not JSON.`, response.status);
  }
}

export async function api<T = R>(path: string, opts: Options = {}): Promise<T> {
  const { baseUrl, token, gen } = current;
  if (!baseUrl) throw new ApiError("disconnected", "No backend connected.");
  if (!controller) rotate();
  const result = await json<T>(await send(baseUrl, token, path, opts, controller!.signal));
  if (gen !== current.gen) throw new ApiError("aborted", "Connection changed");
  return result;
}

export async function download(path: string, params: Record<string, string>, fallbackName: string) {
  const { baseUrl, token, gen } = current;
  if (!baseUrl) throw new ApiError("disconnected", "No backend connected.");
  if (!controller) rotate();
  const response = await send(baseUrl, token, path, { params }, controller!.signal);
  const blob = await response.blob();
  if (gen !== current.gen) throw new ApiError("aborted", "Connection changed");
  const disposition = response.headers.get("Content-Disposition") ?? "";
  const name = /filename="?([^";]+)"?/.exec(disposition)?.[1] ?? fallbackName;
  const href = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = href;
  anchor.download = name;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(href), 1000);
  return blob.size;
}

export type Health = { service?: string; version?: string; auth_required?: boolean };

export async function testConnection(baseUrl: string, token: string, signal?: AbortSignal) {
  const combined = linkSignals([signal, AbortSignal.timeout(15_000)]);
  const health = await json<Health>(await send(baseUrl, "", "/health", { signal: combined }));
  if (!health || health.service !== "SignalWatch") {
    throw new ApiError("invalid", "The URL responded to /health, but not as a SignalWatch backend.");
  }
  const status = await json<R>(await send(baseUrl, token, "/api/status", { signal: combined }));
  if (!status || typeof status !== "object" || !status["stats"] || typeof status["stats"] !== "object") {
    throw new ApiError("invalid", "The backend did not return a SignalWatch status response.");
  }
  return { health, status };
}
