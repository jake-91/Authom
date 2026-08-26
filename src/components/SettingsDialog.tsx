import { useState } from "react";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { api, errorMessage } from "../api";
import type { ImportMode, Settings, VaultStatus } from "../types";
import { ChoicePrompt, Dialog, ErrorBox, Icon, PasswordPrompt } from "./ui";

interface Props {
  settings: Settings;
  status: VaultStatus;
  onClose: () => void;
  onSettingsChanged: (settings: Settings) => void;
  onVaultChanged: () => void;
  onNotice: (message: string, isError?: boolean) => void;
}

/**
 * Multi-step flows live in this state rather than in `window.prompt`/`confirm`,
 * which the webview ignores outright.
 */
type Flow =
  | { kind: "none" }
  | { kind: "export-password" }
  | { kind: "import-password"; path: string }
  | { kind: "import-mode"; path: string; password: string }
  | { kind: "plaintext-warning" };

const AUTO_LOCK_CHOICES: Array<[number, string]> = [
  [0, "사용 안 함"],
  [60, "1분"],
  [300, "5분"],
  [900, "15분"],
  [1800, "30분"],
  [3600, "1시간"],
];

const CLIPBOARD_CHOICES: Array<[number, string]> = [
  [0, "지우지 않음"],
  [10, "10초 후"],
  [30, "30초 후"],
  [60, "1분 후"],
];

export function SettingsDialog({
  settings,
  status,
  onClose,
  onSettingsChanged,
  onVaultChanged,
  onNotice,
}: Props) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [flow, setFlow] = useState<Flow>({ kind: "none" });
  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");

  const patch = async (changes: Partial<Settings>) => {
    setError("");
    try {
      onSettingsChanged(await api.updateSettings({ ...settings, ...changes }));
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const changePassword = async () => {
    setError("");
    if (next !== confirm) {
      setError("새 비밀번호가 일치하지 않습니다.");
      return;
    }
    setBusy(true);
    try {
      await api.changeMasterPassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      setShowPasswordForm(false);
      onNotice("마스터 비밀번호를 변경했습니다.");
      onVaultChanged();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  // ---------------------------------------------------------- backup flows

  const runExport = async (password: string) => {
    setFlow({ kind: "none" });
    setError("");
    const path = await saveDialog({
      title: "암호화 백업 저장",
      defaultPath: "authom-backup.json",
      filters: [{ name: "Authom 백업", extensions: ["json"] }],
    });
    if (!path) return;

    setBusy(true);
    try {
      await api.exportBackup(path, password);
      onNotice("백업을 저장했습니다.");
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const startImport = async () => {
    setError("");
    const selected = await openDialog({
      title: "백업 파일 선택",
      multiple: false,
      filters: [{ name: "Authom 백업", extensions: ["json"] }],
    });
    if (typeof selected !== "string") return;
    setFlow({ kind: "import-password", path: selected });
  };

  const runImport = async (path: string, password: string, mode: ImportMode) => {
    setFlow({ kind: "none" });
    setBusy(true);
    try {
      const summary = await api.importBackup(path, password, mode);
      onNotice(
        `${summary.added}개 복원, 중복 ${summary.skipped_duplicates}개 건너뜀`,
      );
      onVaultChanged();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const runPlaintextExport = async () => {
    setFlow({ kind: "none" });
    setError("");
    const path = await saveDialog({
      title: "평문 내보내기",
      defaultPath: "authom-plaintext.txt",
      filters: [{ name: "텍스트", extensions: ["txt"] }],
    });
    if (!path) return;

    setBusy(true);
    try {
      await api.exportPlaintext(path);
      onNotice("평문 파일을 저장했습니다. 사용 후 삭제하세요.");
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const forgetKey = async () => {
    setError("");
    try {
      await api.forgetSavedKey();
      onNotice("이 기기에 저장된 키를 삭제했습니다.");
      onVaultChanged();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  return (
    <>
      <Dialog
        title="설정"
        onClose={onClose}
        footer={
          <button className="btn primary" onClick={onClose}>
            닫기
          </button>
        }
      >
        <div className="field">
          <label htmlFor="theme">테마</label>
          <select
            id="theme"
            value={settings.theme}
            onChange={(e) => patch({ theme: e.target.value as Settings["theme"] })}
          >
            <option value="system">시스템 설정 따르기</option>
            <option value="light">라이트</option>
            <option value="dark">다크</option>
          </select>
        </div>

        <div className="field">
          <label htmlFor="sort">정렬</label>
          <select
            id="sort"
            value={settings.sort_mode}
            onChange={(e) =>
              patch({ sort_mode: e.target.value as Settings["sort_mode"] })
            }
          >
            <option value="custom">직접 정한 순서 (드래그)</option>
            <option value="issuer">서비스 이름순</option>
            <option value="recent">최근 추가순</option>
          </select>
        </div>

        <div className="field">
          <label htmlFor="autolock">자동 잠금</label>
          <select
            id="autolock"
            value={settings.auto_lock_seconds}
            onChange={(e) => patch({ auto_lock_seconds: Number(e.target.value) })}
          >
            {AUTO_LOCK_CHOICES.map(([value, text]) => (
              <option key={value} value={value}>
                {text}
              </option>
            ))}
          </select>
        </div>

        <div className="field">
          <label htmlFor="clipboard">클립보드 자동 지우기</label>
          <select
            id="clipboard"
            value={settings.clipboard_clear_seconds}
            onChange={(e) =>
              patch({ clipboard_clear_seconds: Number(e.target.value) })
            }
          >
            {CLIPBOARD_CHOICES.map(([value, text]) => (
              <option key={value} value={value}>
                {text}
              </option>
            ))}
          </select>
        </div>

        <label className="checkbox">
          <input
            type="checkbox"
            checked={settings.lock_on_minimize}
            onChange={(e) => patch({ lock_on_minimize: e.target.checked })}
          />
          <span>창을 최소화하면 잠그기</span>
        </label>

        <label className="checkbox">
          <input
            type="checkbox"
            checked={settings.hide_codes}
            onChange={(e) => patch({ hide_codes: e.target.checked })}
          />
          <span>코드를 가리고, 클릭할 때만 표시</span>
        </label>

        <label className="checkbox">
          <input
            type="checkbox"
            checked={settings.compact}
            onChange={(e) => patch({ compact: e.target.checked })}
          />
          <span>좁은 목록 (한 화면에 더 많이)</span>
        </label>

        <div className="menu-sep" />

        {!showPasswordForm ? (
          <button className="btn ghost" onClick={() => setShowPasswordForm(true)}>
            <Icon name="lock" />
            마스터 비밀번호 변경
          </button>
        ) : (
          <>
            <div className="field">
              <label htmlFor="cur-pw">현재 비밀번호</label>
              <input
                id="cur-pw"
                type="password"
                value={current}
                onChange={(e) => setCurrent(e.target.value)}
              />
            </div>
            <div className="field">
              <label htmlFor="new-pw2">새 비밀번호</label>
              <input
                id="new-pw2"
                type="password"
                value={next}
                onChange={(e) => setNext(e.target.value)}
              />
            </div>
            <div className="field">
              <label htmlFor="conf-pw2">새 비밀번호 확인</label>
              <input
                id="conf-pw2"
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
              />
            </div>
            <div className="btn-row">
              <button
                className="btn ghost"
                onClick={() => setShowPasswordForm(false)}
                disabled={busy}
              >
                취소
              </button>
              <button
                className="btn primary"
                onClick={changePassword}
                disabled={busy || !current || next.length < 8}
              >
                변경
              </button>
            </div>
          </>
        )}

        {status.has_remembered_key && (
          <button className="btn ghost" onClick={forgetKey}>
            이 기기에 저장된 키 삭제
          </button>
        )}

        <div className="menu-sep" />

        <button
          className="btn ghost"
          onClick={() => setFlow({ kind: "export-password" })}
          disabled={busy}
        >
          <Icon name="download" />
          암호화 백업 내보내기
        </button>
        <button className="btn ghost" onClick={startImport} disabled={busy}>
          <Icon name="upload" />
          백업에서 복원
        </button>
        <button
          className="btn ghost"
          onClick={() => setFlow({ kind: "plaintext-warning" })}
          disabled={busy}
        >
          <Icon name="eye" />
          평문으로 내보내기 (위험)
        </button>

        <div className="warning-box">
          볼트 파일 위치
          <br />
          <span style={{ wordBreak: "break-all", userSelect: "text" }}>
            {status.vault_path}
          </span>
          <br />
          <br />
          이 파일 하나가 모든 계정입니다. 정기적으로 암호화 백업을 만들고, 각
          서비스의 복구 코드는 이 앱 밖에 따로 보관하세요.
        </div>

        <ErrorBox>{error}</ErrorBox>
      </Dialog>

      {flow.kind === "export-password" && (
        <PasswordPrompt
          title="백업 비밀번호"
          message="백업 파일을 암호화할 비밀번호입니다. 이 비밀번호를 잊으면 백업을 복원할 수 없습니다."
          confirmLabel="계속"
          withConfirmField
          minLength={8}
          onCancel={() => setFlow({ kind: "none" })}
          onSubmit={runExport}
        />
      )}

      {flow.kind === "import-password" && (
        <PasswordPrompt
          title="백업 비밀번호"
          message="선택한 백업 파일을 암호화할 때 쓴 비밀번호를 입력하세요."
          confirmLabel="계속"
          onCancel={() => setFlow({ kind: "none" })}
          onSubmit={(password) =>
            setFlow({ kind: "import-mode", path: flow.path, password })
          }
        />
      )}

      {flow.kind === "import-mode" && (
        <ChoicePrompt
          title="복원 방식"
          message="백업의 항목을 현재 볼트에 어떻게 반영할까요?"
          options={[
            {
              label: "병합",
              description: "백업에만 있는 항목을 추가하고 기존 항목은 그대로 둡니다",
              onPick: () => runImport(flow.path, flow.password, "merge"),
            },
            {
              label: "교체",
              description: "현재 항목을 모두 지우고 백업 내용으로 대체합니다",
              danger: true,
              onPick: () => runImport(flow.path, flow.password, "replace"),
            },
          ]}
          onCancel={() => setFlow({ kind: "none" })}
        />
      )}

      {flow.kind === "plaintext-warning" && (
        <ChoicePrompt
          title="평문으로 내보내기"
          message="모든 2단계 인증 시크릿이 암호화 없이 텍스트 파일에 저장됩니다. 그 파일을 얻은 사람은 누구든 회원님의 모든 계정 코드를 만들 수 있습니다."
          options={[
            {
              label: "그래도 내보내기",
              description: "다른 앱으로 옮긴 뒤 파일을 즉시 삭제하세요",
              danger: true,
              onPick: runPlaintextExport,
            },
          ]}
          onCancel={() => setFlow({ kind: "none" })}
        />
      )}
    </>
  );
}
