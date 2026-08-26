import { useCallback, useEffect, useState } from "react";
import { api, errorMessage } from "../api";
import type { AccountPreview, ImportMode } from "../types";
import { Dialog, ErrorBox, Icon } from "./ui";

interface Props {
  /** URIs already obtained from a scan; when empty the dialog asks for a paste. */
  initialUris: string[];
  onClose: () => void;
  onImported: (message: string) => void;
}

interface Analysis {
  otpauthUris: string[];
  migrationUri: string | null;
  previews: AccountPreview[];
  skipped: string[];
  batch: { size: number; index: number } | null;
}

export function ImportDialog({ initialUris, onClose, onImported }: Props) {
  const [text, setText] = useState(initialUris.join("\n"));
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [mode, setMode] = useState<ImportMode>("merge");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const analyse = useCallback(async (raw: string) => {
    setError("");
    setBusy(true);
    try {
      const lines = raw
        .split(/[\r\n]+/)
        .map((l) => l.trim())
        .filter(Boolean);

      const migrationUri =
        lines.find((l) => l.toLowerCase().startsWith("otpauth-migration://")) ?? null;
      const otpauthUris = lines.filter((l) => l.toLowerCase().startsWith("otpauth://"));

      if (!migrationUri && otpauthUris.length === 0) {
        throw "otpauth:// 또는 otpauth-migration:// URI를 찾지 못했습니다.";
      }

      if (migrationUri) {
        const preview = await api.previewMigration(migrationUri);
        setAnalysis({
          otpauthUris: [],
          migrationUri,
          previews: preview.accounts,
          skipped: preview.skipped,
          batch: { size: preview.batch_size, index: preview.batch_index },
        });
        return;
      }

      const previews: AccountPreview[] = [];
      const skipped: string[] = [];
      for (const uri of otpauthUris) {
        try {
          previews.push(await api.previewUri(uri));
        } catch (e) {
          skipped.push(errorMessage(e));
        }
      }
      if (previews.length === 0) {
        throw skipped.join(" / ") || "가져올 수 있는 항목이 없습니다.";
      }
      setAnalysis({
        otpauthUris,
        migrationUri: null,
        previews,
        skipped,
        batch: null,
      });
    } catch (e) {
      setError(errorMessage(e));
      setAnalysis(null);
    } finally {
      setBusy(false);
    }
  }, []);

  // A scan hands us URIs directly; analyse them without a round trip through
  // the textarea.
  useEffect(() => {
    if (initialUris.length > 0) void analyse(initialUris.join("\n"));
  }, [initialUris, analyse]);

  const commit = async () => {
    if (!analysis) return;
    setError("");
    setBusy(true);
    try {
      const summary = analysis.migrationUri
        ? await api.importMigration(analysis.migrationUri, mode)
        : await api.importUris(analysis.otpauthUris, mode);

      const parts = [`${summary.added}개 추가`];
      if (summary.skipped_duplicates > 0) {
        parts.push(`중복 ${summary.skipped_duplicates}개 건너뜀`);
      }
      onImported(parts.join(", "));
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const newCount = analysis?.previews.filter((p) => !p.duplicate).length ?? 0;

  return (
    <Dialog
      title="가져오기"
      onClose={onClose}
      onSubmit={() => {
        if (busy) return;
        if (analysis) void commit();
        else if (text.trim()) void analyse(text);
      }}
      footer={
        <>
          <button className="btn ghost" onClick={onClose} disabled={busy}>
            취소
          </button>
          {analysis ? (
            <button className="btn primary" onClick={commit} disabled={busy}>
              {mode === "replace" ? "교체하기" : `${newCount}개 가져오기`}
            </button>
          ) : (
            <button
              className="btn primary"
              onClick={() => analyse(text)}
              disabled={busy || !text.trim()}
            >
              분석
            </button>
          )}
        </>
      }
    >
      {!analysis && (
        <>
          <div className="field">
            <label htmlFor="import-text">otpauth URI 붙여넣기</label>
            <textarea
              id="import-text"
              rows={6}
              value={text}
              onChange={(e) => setText(e.target.value)}
              spellCheck={false}
              placeholder={
                "otpauth://totp/GitHub:me@example.com?secret=...\n" +
                "여러 줄을 한 번에 붙여넣을 수 있습니다.\n" +
                "Google Authenticator 내보내기(otpauth-migration://)도 지원합니다."
              }
            />
          </div>
          <p className="hint">
            QR 이미지가 있다면 이 창을 닫고 <strong>추가 → QR 스캔</strong>을
            사용하세요.
          </p>
        </>
      )}

      {analysis && (
        <>
          {analysis.batch && analysis.batch.size > 1 && (
            <div className="warning-box">
              이 내보내기는 QR {analysis.batch.size}장으로 나뉘어 있습니다.
              지금은 {analysis.batch.index + 1}번째만 가져옵니다. 나머지 QR도
              차례로 스캔하세요.
            </div>
          )}

          <div className="hint">
            {analysis.previews.length}개 항목 발견
            {newCount !== analysis.previews.length &&
              ` (이미 있는 항목 ${analysis.previews.length - newCount}개 포함)`}
          </div>

          <div className="preview-list">
            {analysis.previews.map((p, i) => (
              <div className="preview-item" key={`${p.issuer}-${p.label}-${i}`}>
                <span className="name">
                  <strong>{p.issuer || "(발급자 없음)"}</strong>
                  {p.label && ` · ${p.label}`}
                </span>
                {p.kind !== "totp" && <span className="badge">{p.kind.toUpperCase()}</span>}
                {p.duplicate && <span className="badge">중복</span>}
              </div>
            ))}
          </div>

          {analysis.skipped.length > 0 && (
            <div className="warning-box">
              건너뛴 항목 {analysis.skipped.length}개:
              <br />
              {analysis.skipped.slice(0, 3).join(" / ")}
            </div>
          )}

          <div className="field">
            <label htmlFor="import-mode">가져오기 방식</label>
            <select
              id="import-mode"
              value={mode}
              onChange={(e) => setMode(e.target.value as ImportMode)}
            >
              <option value="merge">병합 — 새 항목만 추가</option>
              <option value="replace">교체 — 기존 항목을 모두 지우고 가져오기</option>
            </select>
          </div>

          {mode === "replace" && (
            <div className="warning-box">
              교체를 선택하면 현재 볼트의 모든 항목이 사라집니다. 되돌릴 수
              없습니다.
            </div>
          )}

          <button
            className="btn ghost"
            onClick={() => {
              setAnalysis(null);
              setError("");
            }}
          >
            <Icon name="edit" />
            다시 입력
          </button>
        </>
      )}

      <ErrorBox>{error}</ErrorBox>
    </Dialog>
  );
}
