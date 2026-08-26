import { useState } from "react";
import type { AccountView, CodeView } from "../types";
import { Icon, Ring } from "./ui";

interface Props {
  account: AccountView;
  code: CodeView | undefined;
  compact: boolean;
  hideCodes: boolean;
  draggable: boolean;
  dragging: boolean;
  dropTarget: boolean;
  onCopy: (account: AccountView, code: string) => void;
  onEdit: (account: AccountView) => void;
  onDelete: (account: AccountView) => void;
  onToggleFavorite: (account: AccountView) => void;
  onAdvance: (account: AccountView) => void;
  onDragStart: (id: string) => void;
  onDragOver: (id: string) => void;
  onDrop: () => void;
  onDragEnd: () => void;
}

/** Group digits so a six-digit code reads as "123 456". */
function formatCode(code: string): string {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

export function AccountRow({
  account,
  code,
  compact,
  hideCodes,
  draggable,
  dragging,
  dropTarget,
  onCopy,
  onEdit,
  onDelete,
  onToggleFavorite,
  onAdvance,
  onDragStart,
  onDragOver,
  onDrop,
  onDragEnd,
}: Props) {
  const [revealed, setRevealed] = useState(false);
  const isHotp = account.kind === "hotp";
  const masked = hideCodes && !revealed;
  const expiring = !isHotp && (code?.remaining ?? 99) <= 5;

  const subtitle = [
    account.label || account.issuer,
    account.kind !== "totp" ? account.kind.toUpperCase() : null,
    account.algorithm !== "SHA1" ? account.algorithm : null,
    isHotp ? `#${account.counter}` : null,
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <div
      className={[
        "row",
        compact ? "compact" : "",
        dragging ? "dragging" : "",
        dropTarget ? "drop-target" : "",
      ]
        .filter(Boolean)
        .join(" ")}
      draggable={draggable}
      onDragStart={() => onDragStart(account.id)}
      onDragOver={(e) => {
        e.preventDefault();
        onDragOver(account.id);
      }}
      onDrop={(e) => {
        e.preventDefault();
        onDrop();
      }}
      onDragEnd={onDragEnd}
    >
      {account.color && (
        <div className="row-accent" style={{ background: account.color }} />
      )}

      <div className="row-main">
        <div className="row-title">
          <span>{account.issuer || account.label}</span>
          {account.favorite && (
            <span className="star" title="즐겨찾기">
              <Icon name="star" size={12} />
            </span>
          )}
        </div>

        {code?.error ? (
          <div className="code error" title={code.error}>
            {code.error}
          </div>
        ) : (
          <div
            className={`code${expiring ? " expiring" : ""}${masked ? " hidden-code" : ""}`}
            onClick={() => {
              if (masked) {
                setRevealed(true);
                return;
              }
              if (code?.code) onCopy(account, code.code);
            }}
            title={masked ? "클릭해서 표시" : "클릭해서 복사"}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => {
              if (e.key !== "Enter" && e.key !== " ") return;
              e.preventDefault();
              if (masked) setRevealed(true);
              else if (code?.code) onCopy(account, code.code);
            }}
          >
            {masked ? "••• •••" : formatCode(code?.code ?? "······")}
          </div>
        )}

        <div className="row-sub">{subtitle}</div>
      </div>

      <div className="row-right">
        {isHotp ? (
          <button
            className="icon-btn"
            onClick={() => onAdvance(account)}
            title="다음 코드 생성 (카운터 +1)"
            aria-label="다음 코드"
          >
            <Icon name="refresh" />
          </button>
        ) : (
          <>
            <span className="ring-label">{code?.remaining ?? ""}</span>
            <Ring remaining={code?.remaining ?? 0} period={account.period} />
          </>
        )}

        <button
          className="icon-btn"
          onClick={() => onToggleFavorite(account)}
          title={account.favorite ? "즐겨찾기 해제" : "즐겨찾기"}
          aria-label="즐겨찾기 전환"
        >
          <Icon name="star" />
        </button>
        <button
          className="icon-btn"
          onClick={() => onEdit(account)}
          title="편집"
          aria-label="편집"
        >
          <Icon name="edit" />
        </button>
        <button
          className="icon-btn danger"
          onClick={() => onDelete(account)}
          title="삭제"
          aria-label="삭제"
        >
          <Icon name="trash" />
        </button>
      </div>
    </div>
  );
}
