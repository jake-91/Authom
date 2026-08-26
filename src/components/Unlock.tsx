import { useEffect, useState } from "react";
import { api, errorMessage } from "../api";
import type { VaultStatus } from "../types";
import { ErrorBox, Icon, StrengthMeter } from "./ui";

interface Props {
  status: VaultStatus;
  onUnlocked: (status: VaultStatus) => void;
}

export function Unlock({ status, onUnlocked }: Props) {
  return status.exists ? (
    <UnlockExisting status={status} onUnlocked={onUnlocked} />
  ) : (
    <CreateVault onUnlocked={onUnlocked} />
  );
}

function CreateVault({ onUnlocked }: { onUnlocked: (s: VaultStatus) => void }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [remember, setRemember] = useState(true);
  const [strength, setStrength] = useState(0);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    if (!password) {
      setStrength(0);
      return;
    }
    api
      .passwordStrength(password)
      .then((s) => !cancelled && setStrength(s))
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [password]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (password !== confirm) {
      setError("두 비밀번호가 일치하지 않습니다.");
      return;
    }
    setBusy(true);
    try {
      onUnlocked(await api.createVault(password, remember));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="form-pane" onSubmit={submit}>
      <h1>새 볼트 만들기</h1>
      <p className="hint">
        마스터 비밀번호로 로컬 볼트를 암호화합니다. 이 비밀번호는 어디에도
        전송되지 않으며, 복구 수단도 없습니다.
      </p>

      <div className="field">
        <label htmlFor="new-pw">마스터 비밀번호</label>
        <input
          id="new-pw"
          type="password"
          autoFocus
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="8자 이상"
        />
        <StrengthMeter score={strength} />
      </div>

      <div className="field">
        <label htmlFor="confirm-pw">비밀번호 확인</label>
        <input
          id="confirm-pw"
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
      </div>

      <label className="checkbox">
        <input
          type="checkbox"
          checked={remember}
          onChange={(e) => setRemember(e.target.checked)}
        />
        <span>
          이 기기에서 기억하기
          <br />
          <span className="hint">
            OS 자격 증명 저장소(Windows 자격 증명 관리자 / macOS 키체인)에 키를
            맡겨 다음부터 비밀번호 없이 엽니다.
          </span>
        </span>
      </label>

      <div className="warning-box">
        마스터 비밀번호를 잃어버리면 볼트를 열 수 없습니다. 각 서비스의{" "}
        <strong>백업 코드는 이 앱 밖에</strong> 따로 보관하세요.
      </div>

      <ErrorBox>{error}</ErrorBox>

      <button
        className="btn primary block"
        type="submit"
        disabled={busy || password.length < 8 || !confirm}
      >
        <Icon name="lock" />
        볼트 만들기
      </button>
    </form>
  );
}

function UnlockExisting({
  status,
  onUnlocked,
}: {
  status: VaultStatus;
  onUnlocked: (s: VaultStatus) => void;
}) {
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(status.has_remembered_key);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [triedSavedKey, setTriedSavedKey] = useState(false);

  // If this device already holds the key, open straight away rather than
  // making the user type a password they explicitly asked us to remember.
  useEffect(() => {
    if (!status.has_remembered_key || triedSavedKey) return;
    setTriedSavedKey(true);
    setBusy(true);
    api
      .unlockWithSavedKey()
      .then(onUnlocked)
      .catch((err) => setError(errorMessage(err)))
      .finally(() => setBusy(false));
  }, [status.has_remembered_key, triedSavedKey, onUnlocked]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      onUnlocked(await api.unlockVault(password, remember));
      setPassword("");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="form-pane" onSubmit={submit}>
      <h1>잠금 해제</h1>
      <p className="hint">마스터 비밀번호를 입력하세요.</p>

      <div className="field">
        <label htmlFor="pw">마스터 비밀번호</label>
        <input
          id="pw"
          type="password"
          autoFocus
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </div>

      <label className="checkbox">
        <input
          type="checkbox"
          checked={remember}
          onChange={(e) => setRemember(e.target.checked)}
        />
        <span>이 기기에서 기억하기</span>
      </label>

      <ErrorBox>{error}</ErrorBox>

      <button className="btn primary block" type="submit" disabled={busy || !password}>
        <Icon name="unlock" />
        열기
      </button>

      {status.has_remembered_key && (
        <button
          className="btn ghost block"
          type="button"
          disabled={busy}
          onClick={() => {
            setError("");
            setBusy(true);
            api
              .unlockWithSavedKey()
              .then(onUnlocked)
              .catch((err) => setError(errorMessage(err)))
              .finally(() => setBusy(false));
          }}
        >
          저장된 키로 열기
        </button>
      )}
    </form>
  );
}
