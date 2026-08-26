import type { ReactNode } from "react";
import { useEffect, useRef, useState } from "react";

/** Minimal inline icon set so the bundle stays dependency-free. */
export function Icon({ name, size = 16 }: { name: IconName; size?: number }) {
  const path = ICONS[name];
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {path}
    </svg>
  );
}

export type IconName = keyof typeof ICONS;

const ICONS = {
  lock: (
    <>
      <rect x="3" y="11" width="18" height="11" rx="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </>
  ),
  unlock: (
    <>
      <rect x="3" y="11" width="18" height="11" rx="2" />
      <path d="M7 11V7a5 5 0 0 1 9.9-1" />
    </>
  ),
  plus: (
    <>
      <path d="M12 5v14M5 12h14" />
    </>
  ),
  settings: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9v.09a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </>
  ),
  close: (
    <>
      <path d="M18 6 6 18M6 6l12 12" />
    </>
  ),
  copy: (
    <>
      <rect x="9" y="9" width="13" height="13" rx="2" />
      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
    </>
  ),
  edit: (
    <>
      <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
      <path d="M18.5 2.5a2.12 2.12 0 0 1 3 3L12 15l-4 1 1-4z" />
    </>
  ),
  trash: (
    <>
      <path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6" />
    </>
  ),
  star: (
    <>
      <path d="m12 2 3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01z" />
    </>
  ),
  search: (
    <>
      <circle cx="11" cy="11" r="8" />
      <path d="m21 21-4.35-4.35" />
    </>
  ),
  refresh: (
    <>
      <path d="M21 12a9 9 0 1 1-3-6.7L21 8" />
      <path d="M21 3v5h-5" />
    </>
  ),
  qr: (
    <>
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <path d="M14 14h3v3h-3zM19 19h2v2h-2z" />
    </>
  ),
  eye: (
    <>
      <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  download: (
    <>
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <path d="M7 10l5 5 5-5M12 15V3" />
    </>
  ),
  upload: (
    <>
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <path d="M17 8l-5-5-5 5M12 3v12" />
    </>
  ),
  chevron: (
    <>
      <path d="m9 18 6-6-6-6" />
    </>
  ),
  clock: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </>
  ),
  grip: (
    <>
      <circle cx="9" cy="6" r="1" />
      <circle cx="9" cy="12" r="1" />
      <circle cx="9" cy="18" r="1" />
      <circle cx="15" cy="6" r="1" />
      <circle cx="15" cy="12" r="1" />
      <circle cx="15" cy="18" r="1" />
    </>
  ),
};

/** Countdown ring for time-based entries. */
export function Ring({
  remaining,
  period,
  size = 22,
}: {
  remaining: number;
  period: number;
  size?: number;
}) {
  const radius = (size - 3) / 2;
  const circumference = 2 * Math.PI * radius;
  const ratio = period > 0 ? Math.max(0, Math.min(1, remaining / period)) : 0;
  const expiring = remaining <= 5;

  return (
    <svg
      className={`ring${expiring ? " expiring" : ""}`}
      width={size}
      height={size}
      viewBox={`0 0 ${size} ${size}`}
      role="img"
      aria-label={`${remaining}초 남음`}
    >
      <circle className="track" cx={size / 2} cy={size / 2} r={radius} />
      <circle
        className="value"
        cx={size / 2}
        cy={size / 2}
        r={radius}
        strokeDasharray={circumference}
        strokeDashoffset={circumference * (1 - ratio)}
        strokeLinecap="round"
      />
    </svg>
  );
}

export function Dialog({
  title,
  onClose,
  onSubmit,
  children,
  footer,
  width,
}: {
  title: string;
  onClose: () => void;
  /** Runs on Enter from any single-line field — the dialog's primary action. */
  onSubmit?: () => void;
  children: ReactNode;
  footer?: ReactNode;
  width?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    // Focus the first field so the dialog is immediately usable by keyboard.
    ref.current?.querySelector<HTMLElement>("input, select, textarea, button")?.focus();
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Enter confirms, except in a textarea (newlines) or on a focused control
  // that has its own Enter behaviour.
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (!onSubmit || e.key !== "Enter" || e.shiftKey) return;
    const target = e.target as HTMLElement;
    const tag = target.tagName.toLowerCase();
    if (tag === "textarea" || tag === "button" || tag === "select") return;
    e.preventDefault();
    onSubmit();
  };

  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div
        className="dialog"
        style={width ? { maxWidth: width } : undefined}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onKeyDown={onKeyDown}
      >
        <div className="dialog-head">
          <span>{title}</span>
          <button className="icon-btn" onClick={onClose} aria-label="닫기">
            <Icon name="close" />
          </button>
        </div>
        <div className="dialog-body" ref={ref}>
          {children}
        </div>
        {footer && <div className="dialog-foot">{footer}</div>}
      </div>
    </div>
  );
}

export function StrengthMeter({ score }: { score: number }) {
  return (
    <div className="strength" aria-label={`비밀번호 강도 ${score}/4`}>
      {[1, 2, 3, 4].map((i) => (
        <span key={i} className={score >= i ? `on-${score}` : ""} />
      ))}
    </div>
  );
}

export function ErrorBox({ children }: { children: ReactNode }) {
  if (!children) return null;
  return <div className="error-box">{children}</div>;
}

/**
 * Tauri's webview silently ignores `window.prompt`, so anything that needs a
 * typed secret has to be a real component.
 */
export function PasswordPrompt({
  title,
  message,
  confirmLabel = "확인",
  withConfirmField = false,
  minLength = 1,
  onCancel,
  onSubmit,
}: {
  title: string;
  message: ReactNode;
  confirmLabel?: string;
  withConfirmField?: boolean;
  minLength?: number;
  onCancel: () => void;
  onSubmit: (password: string) => void;
}) {
  const [value, setValue] = useState("");
  const [again, setAgain] = useState("");
  const [error, setError] = useState("");

  const submit = () => {
    if (value.length < minLength) {
      setError(`${minLength}자 이상 입력하세요.`);
      return;
    }
    if (withConfirmField && value !== again) {
      setError("두 비밀번호가 일치하지 않습니다.");
      return;
    }
    onSubmit(value);
  };

  return (
    <Dialog
      title={title}
      onClose={onCancel}
      onSubmit={submit}
      width={360}
      footer={
        <>
          <button className="btn ghost" onClick={onCancel}>
            취소
          </button>
          <button className="btn primary" onClick={submit} disabled={!value}>
            {confirmLabel}
          </button>
        </>
      }
    >
      <p className="hint">{message}</p>
      <div className="field">
        <label htmlFor="prompt-pw">비밀번호</label>
        <input
          id="prompt-pw"
          type="password"
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
            setError("");
          }}
        />
      </div>
      {withConfirmField && (
        <div className="field">
          <label htmlFor="prompt-pw2">비밀번호 확인</label>
          <input
            id="prompt-pw2"
            type="password"
            value={again}
            onChange={(e) => {
              setAgain(e.target.value);
              setError("");
            }}
          />
        </div>
      )}
      <ErrorBox>{error}</ErrorBox>
    </Dialog>
  );
}

/** A modal choice, for decisions a two-button OS dialog would flatten. */
export function ChoicePrompt({
  title,
  message,
  options,
  onCancel,
}: {
  title: string;
  message: ReactNode;
  options: Array<{ label: string; description: string; danger?: boolean; onPick: () => void }>;
  onCancel: () => void;
}) {
  return (
    <Dialog
      title={title}
      onClose={onCancel}
      width={360}
      footer={
        <button className="btn ghost" onClick={onCancel}>
          취소
        </button>
      }
    >
      <p className="hint">{message}</p>
      {options.map((option) => (
        <button
          key={option.label}
          className={`btn ${option.danger ? "danger" : "ghost"}`}
          onClick={option.onPick}
          style={{ flexDirection: "column", alignItems: "flex-start", gap: 2 }}
        >
          <span>{option.label}</span>
          <small style={{ color: "var(--text-dim)", fontWeight: 400 }}>
            {option.description}
          </small>
        </button>
      ))}
    </Dialog>
  );
}
