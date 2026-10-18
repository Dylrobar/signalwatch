import { useEffect, useRef, type ReactNode } from "react";

const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex="0"]';

export function Modal({
  open,
  onClose,
  label,
  variant = "dialog",
  children,
}: {
  open: boolean;
  onClose: () => void;
  label: string;
  variant?: "dialog" | "drawer";
  children: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const opener = useRef<HTMLElement | null>(null);
  const openerRecord = useRef<string | null>(null);
  const close = useRef(onClose);
  close.current = onClose;

  useEffect(() => {
    if (!open) return;
    opener.current = document.activeElement as HTMLElement | null;
    openerRecord.current = opener.current?.closest<HTMLElement>("[data-record-id]")?.dataset["recordId"] ?? null;
    const node = ref.current;
    const first = node?.querySelector<HTMLElement>("[data-autofocus]") ?? node?.querySelector<HTMLElement>(FOCUSABLE);
    (first ?? node)?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        close.current();
        return;
      }
      if (e.key !== "Tab" || !node) return;
      const items = [...node.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((n) => n.getClientRects().length);
      if (!items.length) return e.preventDefault();
      const a = items[0];
      const b = items[items.length - 1];
      if (!a || !b) return e.preventDefault();
      if (!node.contains(document.activeElement)) {
        e.preventDefault();
        a.focus();
      } else if (e.shiftKey && document.activeElement === a) {
        e.preventDefault();
        b.focus();
      } else if (!e.shiftKey && document.activeElement === b) {
        e.preventDefault();
        a.focus();
      }
    };
    document.addEventListener("keydown", onKey, true);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey, true);
      document.body.style.overflow = previousOverflow;
      const target = opener.current?.isConnected
        ? opener.current
        : [...document.querySelectorAll<HTMLElement>("[data-record-id]")].find((row) => row.dataset["recordId"] === openerRecord.current)
          ?? document.querySelector<HTMLElement>('input[type="search"],button[aria-label="Connection settings"]');
      target?.focus();
    };
  }, [open]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-overlay" onClick={onClose} aria-hidden />
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={label}
        tabIndex={-1}
        className={
          variant === "drawer"
            ? "absolute inset-y-0 right-0 flex w-full max-w-2xl flex-col border-l border-border bg-card shadow-2xl"
            : "absolute left-1/2 top-1/2 max-h-[90vh] w-[calc(100%_-_2rem)] max-w-lg -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-lg border border-border bg-card p-5 shadow-2xl"
        }
      >
        {children}
      </div>
    </div>
  );
}
