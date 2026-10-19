import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";
import type { R } from "@/lib/format";

export function WirelessCompanyPicker({
  value,
  onChange,
  gen,
  operator = false,
}: {
  value: string;
  onChange: (value: string) => void;
  gen: number;
  operator?: boolean;
}) {
  const [search, setSearch] = useState("");
  const [term, setTerm] = useState("");
  useEffect(() => {
    const timer = setTimeout(() => setTerm(search.trim()), 250);
    return () => clearTimeout(timer);
  }, [search]);
  const query = useQuery<{ items: R[] }, ApiError>({
    queryKey: ["wireless-companies", gen, term],
    queryFn: ({ signal }) =>
      api("/api/search", { params: { kind: "company", q: term, limit: "30" }, signal }),
    retry: false,
  });
  return (
    <div className="flex min-w-0 flex-wrap gap-2">
      <input
        type="search"
        className="sw-input min-w-0 flex-[1_1_9rem]"
        aria-label={operator ? "Find operator company" : "Find company filter"}
        placeholder="Find company…"
        value={search}
        onChange={(event) => setSearch(event.target.value)}
      />
      <select
        className="sw-input min-w-0 flex-[1_1_12rem]"
        aria-label={operator ? "Operator company" : "Related company"}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      >
        <option value="">{operator ? "Choose a company" : "All company relationships"}</option>
        {value && !query.data?.items.some((item) => item["id"] === value) && (
          <option value={value}>{value}</option>
        )}
        {query.data?.items.map((item) => (
          <option key={String(item["id"])} value={String(item["id"])}>
            {String(item["name"] || item["id"])}
          </option>
        ))}
      </select>
      {query.error && (
        <p role="alert" className="w-full text-xs text-destructive">
          Company search: {query.error.message}
        </p>
      )}
    </div>
  );
}
