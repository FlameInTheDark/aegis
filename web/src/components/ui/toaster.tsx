import * as React from "react";
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from "lucide-react";

import { cn } from "@/lib/utils";

export interface ToastOptions {
  title: string;
  description?: string;
  variant?: "default" | "success" | "warning" | "error";
  duration?: number;
}

interface ToastItem extends ToastOptions {
  id: number;
}

type Listener = (items: ToastItem[]) => void;

let items: ToastItem[] = [];
let seq = 0;
const listeners = new Set<Listener>();

function emit() {
  listeners.forEach((l) => l(items));
}

/** Imperative toast API — usable from anywhere, no context needed. */
export function toast(opts: ToastOptions) {
  const id = ++seq;
  const item: ToastItem = { duration: 3800, variant: "default", ...opts, id };
  items = [...items, item].slice(-4);
  emit();
  window.setTimeout(() => dismiss(id), item.duration);
  return id;
}

export function dismiss(id: number) {
  items = items.filter((t) => t.id !== id);
  emit();
}

const icons = {
  default: Info,
  success: CheckCircle2,
  warning: AlertTriangle,
  error: XCircle,
} as const;

export function Toaster() {
  const [list, setList] = React.useState<ToastItem[]>(items);
  React.useEffect(() => {
    listeners.add(setList);
    return () => {
      listeners.delete(setList);
    };
  }, []);

  return (
    <div className="pointer-events-none fixed bottom-10 right-4 z-[100] flex w-80 flex-col gap-2">
      {list.map((t) => {
        const Icon = icons[t.variant ?? "default"];
        return (
          <div
            key={t.id}
            role="status"
            className={cn(
              "pointer-events-auto relative flex items-start gap-3 rounded-lg border bg-popover p-3 pr-8 text-sm shadow-xl animate-in slide-in-from-right-4 fade-in-0",
              t.variant === "success" && "border-success/40",
              t.variant === "warning" && "border-medium/40",
              t.variant === "error" && "border-critical/40"
            )}
          >
            <Icon
              className={cn(
                "mt-0.5 size-4 shrink-0",
                t.variant === "success" && "text-success",
                t.variant === "warning" && "text-medium",
                t.variant === "error" && "text-critical",
                (!t.variant || t.variant === "default") && "text-primary"
              )}
            />
            <div className="min-w-0">
              <div className="font-medium leading-snug">{t.title}</div>
              {t.description && <div className="mt-0.5 text-xs text-muted-foreground">{t.description}</div>}
            </div>
            <button onClick={() => dismiss(t.id)} className="absolute right-2 top-2 rounded p-0.5 text-muted-foreground hover:text-foreground cursor-pointer">
              <X className="size-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
