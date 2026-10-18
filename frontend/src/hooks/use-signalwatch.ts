import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useSyncExternalStore } from "react";
import { api, ApiError, connection } from "@/lib/api";
import type { R } from "@/lib/format";

export function useConnection() {
  return useSyncExternalStore(connection.subscribe, connection.get, connection.getServer);
}

export function useStatus() {
  const conn = useConnection();
  const qc = useQueryClient();
  const query = useQuery<R, ApiError>({
    queryKey: ["status", conn.gen],
    queryFn: ({ signal }) => api("/api/status", { signal }),
    enabled: Boolean(conn.baseUrl),
    retry: false,
    refetchInterval: (q) => (q.state.data?.["running"] ? 10_000 : 60_000),
    refetchIntervalInBackground: false,
  });
  const prev = useRef<string>("");
  useEffect(() => {
    if (!query.data) return;
    const sig = JSON.stringify([query.data["stats"], query.data["running"]]);
    if (prev.current && prev.current !== sig) qc.invalidateQueries({ queryKey: ["list", conn.gen] });
    prev.current = sig;
  }, [query.data, qc, conn.gen]);
  return { conn, ...query };
}

export type ConnPhase = "disconnected" | "checking" | "connected" | "unauthorized" | "unreachable" | "error";

export function phaseOf(baseUrl: string | null, status: { isPending: boolean; error: ApiError | null; data?: R | undefined }): ConnPhase {
  if (!baseUrl) return "disconnected";
  if (status.error) {
    if (status.error.kind === "unauthorized") return "unauthorized";
    if (status.error.kind === "network") return "unreachable";
    return "error";
  }
  if (status.data) return "connected";
  return "checking";
}
