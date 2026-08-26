import { invoke } from "@tauri-apps/api/core";
import type {
  AccountInput,
  AccountPreview,
  AccountView,
  ClockInfo,
  CodeView,
  ImportMode,
  ImportSummary,
  MigrationPreview,
  ScanResult,
  Settings,
  VaultStatus,
} from "./types";

/**
 * Rust returns its error as a plain string, so anything thrown out of `invoke`
 * is already user-facing. This just guarantees a string for the caller.
 */
export function errorMessage(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}

export const api = {
  vaultStatus: () => invoke<VaultStatus>("vault_status"),

  createVault: (password: string, remember: boolean) =>
    invoke<VaultStatus>("create_vault", { password, remember }),

  unlockVault: (password: string, remember: boolean) =>
    invoke<VaultStatus>("unlock_vault", { password, remember }),

  unlockWithSavedKey: () => invoke<VaultStatus>("unlock_with_saved_key"),

  lockVault: () => invoke<VaultStatus>("lock_vault"),

  forgetSavedKey: () => invoke<VaultStatus>("forget_saved_key"),

  changeMasterPassword: (current: string, newPassword: string) =>
    invoke<void>("change_master_password", { current, newPassword }),

  passwordStrength: (password: string) =>
    invoke<number>("password_strength", { password }),

  touchActivity: () => invoke<void>("touch_activity"),

  listAccounts: () => invoke<AccountView[]>("list_accounts"),

  generateCodes: () => invoke<CodeView[]>("generate_codes"),

  addAccount: (input: AccountInput) =>
    invoke<AccountView>("add_account", { input }),

  updateAccount: (id: string, input: AccountInput) =>
    invoke<AccountView>("update_account", { id, input }),

  deleteAccount: (id: string) => invoke<void>("delete_account", { id }),

  reorderAccounts: (ids: string[]) => invoke<void>("reorder_accounts", { ids }),

  setFavorite: (id: string, favorite: boolean) =>
    invoke<void>("set_favorite", { id, favorite }),

  advanceCounter: (id: string) => invoke<CodeView>("advance_counter", { id }),

  accountUri: (id: string) => invoke<string>("account_uri", { id }),

  previewUri: (input: string) => invoke<AccountPreview>("preview_uri", { input }),

  importUris: (uris: string[], mode: ImportMode) =>
    invoke<ImportSummary>("import_uris", { uris, mode }),

  previewMigration: (input: string) =>
    invoke<MigrationPreview>("preview_migration", { input }),

  importMigration: (input: string, mode: ImportMode) =>
    invoke<ImportSummary>("import_migration", { input, mode }),

  scanQrFile: (path: string) => invoke<ScanResult>("scan_qr_file", { path }),

  scanQrBytes: (bytes: number[]) => invoke<ScanResult>("scan_qr_bytes", { bytes }),

  scanQrRgba: (width: number, height: number, bytes: number[]) =>
    invoke<ScanResult>("scan_qr_rgba", { width, height, bytes }),

  scanQrScreen: () => invoke<ScanResult>("scan_qr_screen"),

  exportBackup: (path: string, password: string) =>
    invoke<void>("export_backup", { path, password }),

  importBackup: (path: string, password: string, mode: ImportMode) =>
    invoke<ImportSummary>("import_backup", { path, password, mode }),

  exportPlaintext: (path: string) => invoke<void>("export_plaintext", { path }),

  importPlaintext: (path: string, mode: ImportMode) =>
    invoke<ImportSummary>("import_plaintext", { path, mode }),

  getSettings: () => invoke<Settings>("get_settings"),

  updateSettings: (settings: Settings) =>
    invoke<Settings>("update_settings", { settings }),

  clockInfo: () => invoke<ClockInfo>("clock_info"),
};
