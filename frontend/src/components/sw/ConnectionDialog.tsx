import { useEffect, useRef, useState } from "react";
import { ApiError, connection, normalizeBaseUrl, testConnection } from "@/lib/api";
import { num, text } from "@/lib/format";
import { Modal } from "./Modal";

type Result = { ok: boolean; lines: string[] };

export function ConnectionDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const conn = connection.get();
  const [url, setUrl] = useState("");
  const [token, setToken] = useState("");
  const [remember, setRemember] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const abort = useRef<AbortController | null>(null);

  useEffect(() => {
    if (!open) return;
    const c = connection.get();
    setUrl(c.baseUrl ?? "");
    setToken(c.token);
    setRemember(c.remember);
    setBusy(false);
    setResult(null);
    return () => {
      abort.current?.abort();
      abort.current = null;
    };
  }, [open]);

  function clearTest() {
    abort.current?.abort();
    abort.current = null;
    setBusy(false);
    setResult(null);
  }

  function parsed() {
    try {
      return normalizeBaseUrl(url);
    } catch (e) {
      setResult({ ok: false, lines: [(e as Error).message] });
      return null;
    }
  }

  async function test(connect = false) {
    const base = parsed();
    if (!base) return;
    abort.current?.abort();
    const attempt = new AbortController();
    abort.current = attempt;
    setBusy(true);
    setResult(null);
    try {
      const { health, status } = await testConnection(base, token.trim(), attempt.signal);
      if (abort.current !== attempt) return;
      setResult({
        ok: true,
        lines: [
          `Health OK · SignalWatch ${text(health.version)} · token ${health.auth_required ? "required" : "not required"}`,
          `Authenticated /api/status OK · ${num(status?.["stats"]?.advisories)} advisories · ${status?.["running"] ? "collection running" : "idle"}`,
          `Requests go to ${base}`,
        ],
      });
      if (connect) {
        connection.set(base, token.trim(), remember);
        onClose();
      }
    } catch (e) {
      if (abort.current !== attempt) return;
      if (e instanceof ApiError && e.kind === "aborted") return;
      const err = e as ApiError;
      const hint =
        err.kind === "unauthorized"
          ? token.trim()
            ? "The backend rejected this token for /api/status."
            : "The backend requires a Bearer token (SIGNALWATCH_API_TOKEN)."
          : err.kind === "network"
            ? "Network or CORS failure."
            : err.kind === "invalid"
              ? "Unexpected response."
              : "Backend returned an error.";
      setResult({ ok: false, lines: [hint, err.message] });
    } finally {
      if (abort.current === attempt) setBusy(false);
    }
  }

  function save() {
    void test(true);
  }

  const isLocal = /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(url.trim());

  return (
    <Modal open={open} onClose={onClose} label="Backend connection">
      <h2 className="text-base font-semibold">Backend connection</h2>
      <p className="mt-1 text-xs text-muted-foreground">
        Connect this dashboard to your separately hosted SignalWatch Python API. The URL is remembered in this browser; the token is
        kept in memory unless you choose to keep it for this tab session.
      </p>
      <form
        className="mt-4 space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          save();
        }}
      >
        <div>
          <label className="sw-label" htmlFor="sw-url">
            API base URL
          </label>
          <input
            id="sw-url"
            data-autofocus
            className="sw-input font-mono"
            placeholder="https://signalwatch.example.org"
            value={url}
            onChange={(e) => { clearTest(); setUrl(e.target.value); }}
            autoComplete="url"
            inputMode="url"
          />
          <p className="mt-1 text-[11px] text-muted-foreground">
            HTTPS required. A path prefix is kept (…/signalwatch → …/signalwatch/api/status). HTTP is allowed only for localhost.
          </p>
          {isLocal && (
            <p className="mt-1 text-[11px] text-warn">
              localhost means the computer running this browser, not a hosted server. It only works if the backend runs on your machine
              and allows this site's origin.
            </p>
          )}
        </div>
        <div>
          <label className="sw-label" htmlFor="sw-token">
            Bearer token (optional)
          </label>
          <input
            id="sw-token"
            type="password"
            className="sw-input font-mono"
            value={token}
            onChange={(e) => { clearTest(); setToken(e.target.value); }}
            autoComplete="off"
          />
          <label className="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
            <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
            Keep token for this browser tab session (cleared when the tab closes)
          </label>
        </div>
        {result && (
          <div
            role="status"
            className={`rounded-md border p-2 text-xs ${result.ok ? "border-primary/50 text-primary" : "border-destructive/50 text-destructive"}`}
          >
            {result.lines.map((l) => (
              <div key={l} className="break-words">
                {l}
              </div>
            ))}
          </div>
        )}
        <div className="flex flex-wrap gap-2 pt-1">
          <button type="button" className="sw-btn" onClick={() => void test()} disabled={busy}>
            {busy ? "Testing…" : "Test connection"}
          </button>
          <button type="submit" className="sw-btn-primary" disabled={busy}>
            Save & connect
          </button>
          {conn.baseUrl && (
            <button
              type="button"
              className="sw-btn-danger"
              onClick={() => {
                connection.clear();
                onClose();
              }}
            >
              Disconnect
            </button>
          )}
          <button type="button" className="sw-btn ml-auto" onClick={onClose}>
            Cancel
          </button>
        </div>
      </form>
    </Modal>
  );
}
