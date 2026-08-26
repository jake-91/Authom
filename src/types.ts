export type OtpKind = "totp" | "hotp" | "steam";
export type Algorithm = "SHA1" | "SHA256" | "SHA512";
export type ImportMode = "merge" | "replace";

export interface VaultStatus {
  exists: boolean;
  unlocked: boolean;
  has_remembered_key: boolean;
  vault_path: string;
  account_count: number;
}

export interface AccountView {
  id: string;
  kind: OtpKind;
  issuer: string;
  label: string;
  algorithm: Algorithm;
  digits: number;
  period: number;
  counter: number;
  group: string | null;
  notes: string | null;
  favorite: boolean;
  color: string | null;
  created_at: number;
  updated_at: number;
  sort_index: number;
}

export interface CodeView {
  id: string;
  code: string;
  next_code: string | null;
  remaining: number;
  period: number;
  counter: number;
  error: string | null;
}

export interface AccountInput {
  kind: OtpKind;
  issuer: string;
  label: string;
  secret: string | null;
  algorithm: Algorithm;
  digits: number;
  period: number;
  counter: number | null;
  group: string | null;
  notes: string | null;
  favorite: boolean | null;
  color: string | null;
}

export interface AccountPreview {
  kind: OtpKind;
  issuer: string;
  label: string;
  algorithm: Algorithm;
  digits: number;
  period: number;
  counter: number;
  secret_length: number;
  duplicate: boolean;
}

export interface MigrationPreview {
  accounts: AccountPreview[];
  batch_size: number;
  batch_index: number;
  skipped: string[];
}

export interface ScanResult {
  uris: string[];
  otpauth_count: number;
  migration_count: number;
}

export interface ImportSummary {
  added: number;
  skipped_duplicates: number;
  total_in_file: number;
}

export interface Settings {
  auto_lock_seconds: number;
  clipboard_clear_seconds: number;
  hide_codes: boolean;
  theme: "system" | "light" | "dark";
  sort_mode: "custom" | "issuer" | "recent";
  lock_on_minimize: boolean;
  compact: boolean;
}

export interface ClockInfo {
  unix: number;
  step_remaining_30s: number;
}

export const DEFAULT_SETTINGS: Settings = {
  auto_lock_seconds: 300,
  clipboard_clear_seconds: 30,
  hide_codes: false,
  theme: "system",
  sort_mode: "custom",
  lock_on_minimize: true,
  compact: false,
};

/** Palette offered when tagging an entry with a colour. */
export const ACCENT_COLORS = [
  "#38bdf8",
  "#34d399",
  "#fbbf24",
  "#fb7185",
  "#a78bfa",
  "#f97316",
  "#94a3b8",
] as const;
