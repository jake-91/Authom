import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import {
  readImage,
  readText,
  writeText,
} from "@tauri-apps/plugin-clipboard-manager";
import { api, errorMessage } from "./api";
import { DEFAULT_SETTINGS } from "./types";
import type {
  AccountView,
  CodeView,
  Settings,
  VaultStatus,
} from "./types";
import { AccountDialog } from "./components/AccountDialog";
import { AccountRow } from "./components/AccountRow";
import { ImportDialog } from "./components/ImportDialog";
import { SettingsDialog } from "./components/SettingsDialog";
import { Unlock } from "./components/Unlock";
import { ChoicePrompt, Icon } from "./components/ui";

type DialogState =
  | { kind: "none" }
  | { kind: "account"; account: AccountView | null }
  | { kind: "import"; uris: string[] }
  | { kind: "settings" };

interface Toast {
  message: string;
  isError: boolean;
}

export default function App() {
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [accounts, setAccounts] = useState<AccountView[]>([]);
  const [codes, setCodes] = useState<Record<string, CodeView>>({});
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [query, setQuery] = useState("");
  const [dialog, setDialog] = useState<DialogState>({ kind: "none" });
  const [menuOpen, setMenuOpen] = useState(false);
  const [toast, setToast] = useState<Toast | null>(null);
  const [dragId, setDragId] = useState<string | null>(null);
  const [dropId, setDropId] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<AccountView | null>(null);

  const searchRef = useRef<HTMLInputElement>(null);
  const clipboardTimer = useRef<number | null>(null);
  const toastTimer = useRef<number | null>(null);

  const unlocked = status?.unlocked ?? false;

  // ------------------------------------------------------------ notices

  const notify = useCallback((message: string, isError = false) => {
    setToast({ message, isError });
    if (toastTimer.current) window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(null), 2600);
  }, []);

  // ------------------------------------------------------------ data loading

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await api.vaultStatus());
    } catch (e) {
      notify(errorMessage(e), true);
    }
  }, [notify]);

  const reload = useCallback(async () => {
    try {
      const [list, loadedSettings, currentCodes] = await Promise.all([
        api.listAccounts(),
        api.getSettings(),
        api.generateCodes(),
      ]);
      setAccounts(list);
      setSettings(loadedSettings);
      setCodes(Object.fromEntries(currentCodes.map((c) => [c.id, c])));
    } catch (e) {
      // Locking mid-refresh is normal, not something to shout about.
      if (!String(e).includes("잠겨")) notify(errorMessage(e), true);
    }
  }, [notify]);

  useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  useEffect(() => {
    if (unlocked) void reload();
    else setAccounts([]);
  }, [unlocked, reload]);

  // ------------------------------------------------------------ code ticker

  useEffect(() => {
    if (!unlocked) return;
    let alive = true;

    const tick = async () => {
      try {
        const list = await api.generateCodes();
        if (alive) setCodes(Object.fromEntries(list.map((c) => [c.id, c])));
      } catch {
        // The vault locked between ticks; the lock listener handles the UI.
      }
    };

    void tick();
    const handle = window.setInterval(tick, 1000);
    return () => {
      alive = false;
      window.clearInterval(handle);
    };
  }, [unlocked]);

  // ------------------------------------------------------------ lock handling

  useEffect(() => {
    const unlistenPromise = listen("vault-locked", () => {
      setDialog({ kind: "none" });
      setMenuOpen(false);
      setQuery("");
      void refreshStatus();
      notify("자동으로 잠겼습니다.");
    });
    return () => {
      void unlistenPromise.then((un) => un());
    };
  }, [refreshStatus, notify]);

  // Minimising hides the webview, which is the signal we use for "the user
  // stepped away from the window".
  useEffect(() => {
    if (!unlocked || !settings.lock_on_minimize) return;
    const onVisibility = () => {
      if (document.visibilityState === "hidden") {
        void api.lockVault().then(setStatus);
      }
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => document.removeEventListener("visibilitychange", onVisibility);
  }, [unlocked, settings.lock_on_minimize]);

  // Any interaction counts as activity for the idle timer.
  useEffect(() => {
    if (!unlocked) return;
    let last = 0;
    const onActivity = () => {
      const now = Date.now();
      if (now - last < 5000) return;
      last = now;
      void api.touchActivity();
    };
    window.addEventListener("pointerdown", onActivity);
    window.addEventListener("keydown", onActivity);
    return () => {
      window.removeEventListener("pointerdown", onActivity);
      window.removeEventListener("keydown", onActivity);
    };
  }, [unlocked]);

  const lockNow = useCallback(async () => {
    setDialog({ kind: "none" });
    setMenuOpen(false);
    setQuery("");
    setStatus(await api.lockVault());
  }, []);

  // ------------------------------------------------------------ theme

  useEffect(() => {
    const root = document.documentElement;
    const media = window.matchMedia("(prefers-color-scheme: dark)");

    const apply = () => {
      const dark =
        settings.theme === "dark" ||
        (settings.theme === "system" && media.matches);
      root.setAttribute("data-theme", dark ? "dark" : "light");
    };

    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [settings.theme]);

  // ------------------------------------------------------------ shortcuts

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!e.ctrlKey && !e.metaKey) return;
      if (e.key === "f") {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (e.key === "l") {
        e.preventDefault();
        if (unlocked) void lockNow();
      } else if (e.key === "n") {
        e.preventDefault();
        if (unlocked) setDialog({ kind: "account", account: null });
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [unlocked, lockNow]);

  // ------------------------------------------------------------ clipboard

  const copyText = useCallback(
    async (text: string, description: string) => {
      try {
        await writeText(text);
        if (clipboardTimer.current) window.clearTimeout(clipboardTimer.current);

        const seconds = settings.clipboard_clear_seconds;
        if (seconds > 0) {
          clipboardTimer.current = window.setTimeout(() => {
            // Overwriting is the portable way to clear across platforms.
            void writeText("").catch(() => undefined);
          }, seconds * 1000);
          notify(`${description} 복사됨 · ${seconds}초 후 자동 삭제`);
        } else {
          notify(`${description} 복사됨`);
        }
      } catch (e) {
        notify(errorMessage(e), true);
      }
    },
    [settings.clipboard_clear_seconds, notify],
  );

  const copyCode = useCallback(
    (account: AccountView, code: string) =>
      copyText(code, account.issuer || account.label),
    [copyText],
  );

  // ------------------------------------------------------------ scanning

  const openImport = (uris: string[]) => {
    setMenuOpen(false);
    setDialog({ kind: "import", uris });
  };

  const scanScreen = async () => {
    setMenuOpen(false);
    try {
      const result = await api.scanQrScreen();
      if (result.uris.length === 0) {
        notify("화면에서 QR 코드를 찾지 못했습니다.", true);
        return;
      }
      openImport(result.uris);
    } catch (e) {
      notify(errorMessage(e), true);
    }
  };

  const scanFile = async () => {
    setMenuOpen(false);
    try {
      const selected = await openDialog({
        title: "QR 이미지 선택",
        multiple: false,
        filters: [
          { name: "이미지", extensions: ["png", "jpg", "jpeg", "bmp", "gif", "webp"] },
        ],
      });
      if (typeof selected !== "string") return;

      const result = await api.scanQrFile(selected);
      if (result.uris.length === 0) {
        notify("이미지에서 QR 코드를 찾지 못했습니다.", true);
        return;
      }
      openImport(result.uris);
    } catch (e) {
      notify(errorMessage(e), true);
    }
  };

  const scanClipboard = async () => {
    setMenuOpen(false);
    try {
      // Text first: a pasted otpauth URI is the common case.
      const text = await readText().catch(() => "");
      if (text && text.toLowerCase().includes("otpauth")) {
        openImport(
          text
            .split(/[\r\n]+/)
            .map((l) => l.trim())
            .filter((l) => l.toLowerCase().startsWith("otpauth")),
        );
        return;
      }

      const image = await readImage();
      const size = await image.size();
      const rgba = await image.rgba();
      const result = await api.scanQrRgba(
        size.width,
        size.height,
        Array.from(rgba),
      );
      if (result.uris.length === 0) {
        notify("클립보드 이미지에서 QR 코드를 찾지 못했습니다.", true);
        return;
      }
      openImport(result.uris);
    } catch {
      notify("클립보드에 QR 이미지나 otpauth URI가 없습니다.", true);
    }
  };

  // ------------------------------------------------------------ account actions

  // The webview ignores window.confirm, so a destructive action needs a real
  // modal — otherwise a stray click deletes an entry with no way back.
  const deleteAccount = async (account: AccountView) => {
    setPendingDelete(account);
  };

  const confirmDelete = async () => {
    const account = pendingDelete;
    setPendingDelete(null);
    if (!account) return;
    try {
      await api.deleteAccount(account.id);
      notify("삭제했습니다.");
      await reload();
    } catch (e) {
      notify(errorMessage(e), true);
    }
  };

  const toggleFavorite = async (account: AccountView) => {
    try {
      await api.setFavorite(account.id, !account.favorite);
      await reload();
    } catch (e) {
      notify(errorMessage(e), true);
    }
  };

  const advance = async (account: AccountView) => {
    try {
      const code = await api.advanceCounter(account.id);
      setCodes((c) => ({ ...c, [code.id]: code }));
      await reload();
    } catch (e) {
      notify(errorMessage(e), true);
    }
  };

  // ------------------------------------------------------------ ordering

  const sorted = useMemo(() => {
    const list = [...accounts];
    if (settings.sort_mode === "issuer") {
      list.sort((a, b) =>
        (a.issuer || a.label).localeCompare(b.issuer || b.label, "ko"),
      );
    } else if (settings.sort_mode === "recent") {
      list.sort((a, b) => b.created_at - a.created_at);
    } else {
      list.sort((a, b) => a.sort_index - b.sort_index);
    }
    // Favourites always float to the top, whatever the sort mode.
    return list.sort((a, b) => Number(b.favorite) - Number(a.favorite));
  }, [accounts, settings.sort_mode]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return sorted;
    return sorted.filter((a) =>
      [a.issuer, a.label, a.group ?? "", a.notes ?? ""]
        .join(" ")
        .toLowerCase()
        .includes(q),
    );
  }, [sorted, query]);

  const grouped = useMemo(() => {
    const map = new Map<string, AccountView[]>();
    for (const account of filtered) {
      const key = account.group ?? "";
      const bucket = map.get(key);
      if (bucket) bucket.push(account);
      else map.set(key, [account]);
    }
    return [...map.entries()].sort(([a], [b]) => {
      if (a === "") return -1;
      if (b === "") return 1;
      return a.localeCompare(b, "ko");
    });
  }, [filtered]);

  const groupNames = useMemo(
    () =>
      [...new Set(accounts.map((a) => a.group).filter((g): g is string => !!g))].sort(),
    [accounts],
  );

  const dragEnabled = settings.sort_mode === "custom" && !query.trim();

  const finishDrag = async () => {
    if (!dragId || !dropId || dragId === dropId) {
      setDragId(null);
      setDropId(null);
      return;
    }
    const ids = sorted.map((a) => a.id);
    const from = ids.indexOf(dragId);
    const to = ids.indexOf(dropId);
    setDragId(null);
    setDropId(null);
    if (from < 0 || to < 0) return;

    ids.splice(to, 0, ids.splice(from, 1)[0]);
    try {
      await api.reorderAccounts(ids);
      await reload();
    } catch (e) {
      notify(errorMessage(e), true);
    }
  };

  // ------------------------------------------------------------ render

  if (!status) {
    return (
      <div className="app">
        <div className="center-pane">불러오는 중…</div>
      </div>
    );
  }

  if (!unlocked) {
    return (
      <div className="app">
        <Unlock status={status} onUnlocked={setStatus} />
        {toast && (
          <div className={`toast${toast.isError ? " error" : ""}`}>{toast.message}</div>
        )}
      </div>
    );
  }

  return (
    <div className="app">
      <div className="topbar">
        <div className="brand">
          <span className="brand-mark">
            <Icon name="lock" size={12} />
          </span>
          Authom
        </div>

        <button
          className="icon-btn"
          onClick={() => setMenuOpen((m) => !m)}
          title="추가 (Ctrl+N)"
          aria-label="항목 추가"
        >
          <Icon name="plus" />
        </button>
        <button
          className="icon-btn"
          onClick={() => setDialog({ kind: "settings" })}
          title="설정"
          aria-label="설정"
        >
          <Icon name="settings" />
        </button>
        <button
          className="icon-btn"
          onClick={lockNow}
          title="잠그기 (Ctrl+L)"
          aria-label="잠그기"
        >
          <Icon name="lock" />
        </button>
      </div>

      {menuOpen && (
        <>
          <div
            style={{ position: "fixed", inset: 0, zIndex: 29 }}
            onClick={() => setMenuOpen(false)}
          />
          <div className="menu">
            <button
              onClick={() => {
                setMenuOpen(false);
                setDialog({ kind: "account", account: null });
              }}
            >
              직접 입력
              <small>서비스가 알려준 시크릿을 손으로 입력</small>
            </button>
            <button onClick={scanScreen}>
              화면에서 QR 스캔
              <small>브라우저에 띄운 QR을 그대로 인식</small>
            </button>
            <button onClick={scanFile}>
              QR 이미지 파일 열기
              <small>저장해 둔 QR 스크린샷</small>
            </button>
            <button onClick={scanClipboard}>
              클립보드에서 가져오기
              <small>복사한 QR 이미지 또는 otpauth URI</small>
            </button>
            <div className="menu-sep" />
            <button onClick={() => openImport([])}>
              URI 붙여넣기 / 일괄 가져오기
              <small>Google Authenticator 내보내기 포함</small>
            </button>
          </div>
        </>
      )}

      <div className="searchbar">
        <input
          ref={searchRef}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="검색 (Ctrl+F)"
          spellCheck={false}
        />
      </div>

      {accounts.length === 0 ? (
        <div className="center-pane">
          <h2>아직 항목이 없습니다</h2>
          <p>
            오른쪽 위 <strong>+</strong> 버튼으로 QR을 스캔하거나 시크릿을
            직접 입력해 첫 계정을 추가하세요.
          </p>
          <button
            className="btn primary"
            onClick={() => setDialog({ kind: "account", account: null })}
          >
            <Icon name="plus" />
            항목 추가
          </button>
        </div>
      ) : filtered.length === 0 ? (
        <div className="center-pane">
          <p>'{query}'와 일치하는 항목이 없습니다.</p>
        </div>
      ) : (
        <div className="list">
          {grouped.map(([group, items]) => (
            <div key={group || "__ungrouped"}>
              {group && <div className="group-heading">{group}</div>}
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {items.map((account) => (
                  <AccountRow
                    key={account.id}
                    account={account}
                    code={codes[account.id]}
                    compact={settings.compact}
                    hideCodes={settings.hide_codes}
                    draggable={dragEnabled}
                    dragging={dragId === account.id}
                    dropTarget={dropId === account.id && dragId !== account.id}
                    onCopy={copyCode}
                    onEdit={(a) => setDialog({ kind: "account", account: a })}
                    onDelete={deleteAccount}
                    onToggleFavorite={toggleFavorite}
                    onAdvance={advance}
                    onDragStart={setDragId}
                    onDragOver={setDropId}
                    onDrop={finishDrag}
                    onDragEnd={() => {
                      setDragId(null);
                      setDropId(null);
                    }}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="footer-bar">
        <Icon name="clock" size={12} />
        <span>기기 시계 기준 · 코드가 계속 거부되면 시간 동기화를 확인하세요</span>
        <span className="spacer">{accounts.length}개</span>
      </div>

      {dialog.kind === "account" && (
        <AccountDialog
          account={dialog.account}
          groups={groupNames}
          onClose={() => setDialog({ kind: "none" })}
          onSaved={() => {
            void reload();
            notify(dialog.account ? "저장했습니다." : "추가했습니다.");
          }}
          onCopyText={copyText}
        />
      )}

      {dialog.kind === "import" && (
        <ImportDialog
          initialUris={dialog.uris}
          onClose={() => setDialog({ kind: "none" })}
          onImported={(message) => {
            void reload();
            notify(message);
          }}
        />
      )}

      {dialog.kind === "settings" && (
        <SettingsDialog
          settings={settings}
          status={status}
          onClose={() => setDialog({ kind: "none" })}
          onSettingsChanged={setSettings}
          onVaultChanged={() => {
            void refreshStatus();
            void reload();
          }}
          onNotice={notify}
        />
      )}

      {pendingDelete && (
        <ChoicePrompt
          title="항목 삭제"
          message={
            <>
              <strong>
                {pendingDelete.issuer || pendingDelete.label}
                {pendingDelete.issuer && pendingDelete.label
                  ? ` (${pendingDelete.label})`
                  : ""}
              </strong>
              {" 항목을 삭제합니다. 되돌릴 수 없으며, 다시 쓰려면 해당 서비스에서 2단계 인증을 재등록해야 합니다."}
            </>
          }
          options={[
            {
              label: "삭제",
              description: "이 항목을 볼트에서 영구히 제거합니다",
              danger: true,
              onPick: confirmDelete,
            },
          ]}
          onCancel={() => setPendingDelete(null)}
        />
      )}

      {toast && (
        <div className={`toast${toast.isError ? " error" : ""}`}>{toast.message}</div>
      )}
    </div>
  );
}
