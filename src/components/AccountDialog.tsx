import { useState } from "react";
import { api, errorMessage } from "../api";
import { ACCENT_COLORS } from "../types";
import type { AccountInput, AccountView, Algorithm, OtpKind } from "../types";
import { Dialog, ErrorBox, Icon } from "./ui";

interface Props {
  account: AccountView | null;
  groups: string[];
  onClose: () => void;
  onSaved: () => void;
  onCopyText: (text: string, description: string) => void;
}

const EMPTY: AccountInput = {
  kind: "totp",
  issuer: "",
  label: "",
  secret: "",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  counter: 0,
  group: null,
  notes: null,
  favorite: false,
  color: null,
};

export function AccountDialog({
  account,
  groups,
  onClose,
  onSaved,
  onCopyText,
}: Props) {
  const editing = account !== null;
  const [form, setForm] = useState<AccountInput>(
    account
      ? {
          kind: account.kind,
          issuer: account.issuer,
          label: account.label,
          // Left blank on edit; an empty value keeps the stored secret.
          secret: "",
          algorithm: account.algorithm,
          digits: account.digits,
          period: account.period,
          counter: account.counter,
          group: account.group,
          notes: account.notes,
          favorite: account.favorite,
          color: account.color,
        }
      : EMPTY,
  );
  const [advanced, setAdvanced] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [revealedUri, setRevealedUri] = useState<string | null>(null);

  const set = <K extends keyof AccountInput>(key: K, value: AccountInput[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  const steam = form.kind === "steam";

  const save = async () => {
    setError("");
    setBusy(true);
    try {
      if (editing) {
        await api.updateAccount(account.id, form);
      } else {
        await api.addAccount(form);
      }
      onSaved();
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const revealSecret = async () => {
    if (!account) return;
    try {
      setRevealedUri(await api.accountUri(account.id));
    } catch (err) {
      setError(errorMessage(err));
    }
  };

  return (
    <Dialog
      title={editing ? "항목 편집" : "항목 추가"}
      onClose={onClose}
      onSubmit={() => {
        if (!busy) void save();
      }}
      footer={
        <>
          <button className="btn ghost" onClick={onClose} disabled={busy}>
            취소
          </button>
          <button className="btn primary" onClick={save} disabled={busy}>
            저장
          </button>
        </>
      }
    >
      <div className="field">
        <label htmlFor="issuer">서비스 (발급자)</label>
        <input
          id="issuer"
          value={form.issuer}
          onChange={(e) => set("issuer", e.target.value)}
          placeholder="예: Google, Microsoft"
        />
      </div>

      <div className="field">
        <label htmlFor="label">계정 이름</label>
        <input
          id="label"
          value={form.label}
          onChange={(e) => set("label", e.target.value)}
          placeholder="예: me@example.com"
        />
      </div>

      <div className="field">
        <label htmlFor="secret">
          시크릿 (base32){editing && " — 비워두면 기존 값 유지"}
        </label>
        <input
          id="secret"
          value={form.secret ?? ""}
          onChange={(e) => set("secret", e.target.value)}
          placeholder={editing ? "변경할 때만 입력" : "JBSW Y3DP EHPK 3PXP"}
          spellCheck={false}
          autoComplete="off"
        />
      </div>

      <div className="field">
        <label htmlFor="group">그룹</label>
        <input
          id="group"
          list="group-options"
          value={form.group ?? ""}
          onChange={(e) => set("group", e.target.value || null)}
          placeholder="선택 사항"
        />
        <datalist id="group-options">
          {groups.map((g) => (
            <option key={g} value={g} />
          ))}
        </datalist>
      </div>

      <div className="field">
        <label>색상</label>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          <button
            type="button"
            onClick={() => set("color", null)}
            title="없음"
            style={{
              width: 24,
              height: 24,
              borderRadius: 6,
              border: `2px solid ${form.color === null ? "var(--accent)" : "var(--border)"}`,
            }}
          />
          {ACCENT_COLORS.map((c) => (
            <button
              key={c}
              type="button"
              onClick={() => set("color", c)}
              title={c}
              style={{
                width: 24,
                height: 24,
                borderRadius: 6,
                background: c,
                border: `2px solid ${form.color === c ? "var(--text)" : "transparent"}`,
              }}
            />
          ))}
        </div>
      </div>

      <button
        className="btn ghost"
        type="button"
        onClick={() => setAdvanced((a) => !a)}
        style={{ justifyContent: "space-between" }}
      >
        고급 설정
        <span
          style={{
            transform: advanced ? "rotate(90deg)" : "none",
            display: "inline-flex",
          }}
        >
          <Icon name="chevron" />
        </span>
      </button>

      {advanced && (
        <>
          <div className="field-row">
            <div className="field">
              <label htmlFor="kind">종류</label>
              <select
                id="kind"
                value={form.kind}
                onChange={(e) => set("kind", e.target.value as OtpKind)}
              >
                <option value="totp">TOTP (시간 기반)</option>
                <option value="hotp">HOTP (카운터 기반)</option>
                <option value="steam">Steam Guard</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="algorithm">알고리즘</label>
              <select
                id="algorithm"
                value={form.algorithm}
                disabled={steam}
                onChange={(e) => set("algorithm", e.target.value as Algorithm)}
              >
                <option value="SHA1">SHA1</option>
                <option value="SHA256">SHA256</option>
                <option value="SHA512">SHA512</option>
              </select>
            </div>
          </div>

          <div className="field-row">
            <div className="field">
              <label htmlFor="digits">자릿수</label>
              <input
                id="digits"
                type="number"
                min={6}
                max={9}
                disabled={steam}
                value={form.digits}
                onChange={(e) => set("digits", Number(e.target.value))}
              />
            </div>
            {form.kind === "hotp" ? (
              <div className="field">
                <label htmlFor="counter">카운터</label>
                <input
                  id="counter"
                  type="number"
                  min={0}
                  value={form.counter ?? 0}
                  onChange={(e) => set("counter", Number(e.target.value))}
                />
              </div>
            ) : (
              <div className="field">
                <label htmlFor="period">주기 (초)</label>
                <input
                  id="period"
                  type="number"
                  min={5}
                  max={300}
                  disabled={steam}
                  value={form.period}
                  onChange={(e) => set("period", Number(e.target.value))}
                />
              </div>
            )}
          </div>

          <div className="field">
            <label htmlFor="notes">메모</label>
            <textarea
              id="notes"
              rows={2}
              value={form.notes ?? ""}
              onChange={(e) => set("notes", e.target.value || null)}
            />
          </div>

          {editing && (
            <>
              <button className="btn ghost" type="button" onClick={revealSecret}>
                <Icon name="eye" />
                시크릿 / otpauth URI 보기
              </button>
              {revealedUri && (
                <>
                  <div className="warning-box">
                    아래 문자열에는 이 계정의 시크릿이 그대로 들어 있습니다.
                    화면 공유 중이라면 즉시 닫으세요.
                  </div>
                  <div className="secret-reveal">{revealedUri}</div>
                  <button
                    className="btn ghost"
                    type="button"
                    onClick={() => onCopyText(revealedUri, "otpauth URI")}
                  >
                    <Icon name="copy" />
                    URI 복사
                  </button>
                </>
              )}
            </>
          )}
        </>
      )}

      <ErrorBox>{error}</ErrorBox>
    </Dialog>
  );
}
