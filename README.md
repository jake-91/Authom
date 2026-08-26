# Authom

로컬 전용 2단계 인증(OTP) 관리 앱. Google Authenticator, Microsoft Authenticator가 쓰는
표준 TOTP/HOTP를 그대로 지원하며, 모든 데이터는 이 기기의 암호화된 파일 하나에만 저장됩니다.
네트워크 통신은 전혀 하지 않습니다.

Windows / macOS 크로스 플랫폼 (Tauri v2 + React + Rust).

## 기능

- **TOTP** (RFC 6238), **HOTP** (RFC 4226), **Steam Guard** 변종
- SHA1 / SHA256 / SHA512, 6~9자리, 5~300초 주기
- QR 코드 인식: **화면 캡처**, 이미지 파일, 클립보드 이미지
- `otpauth://` URI 붙여넣기 (여러 줄 일괄)
- **Google Authenticator 내보내기**(`otpauth-migration://`) 가져오기
- 암호화 백업 내보내기 / 복원, 평문 내보내기(경고 후)
- 그룹, 즐겨찾기, 색상 태그, 검색, 드래그 정렬
- 자동 잠금, 최소화 시 잠금, 클립보드 자동 삭제
- 다크 / 라이트 / 시스템 테마

## 보안 설계

| 항목 | 방식 |
|---|---|
| 키 파생 | Argon2id (64 MiB, t=3, p=4) |
| 암호화 | XChaCha20-Poly1305 (AEAD), 저장할 때마다 논스 회전 |
| 무결성 | KDF 헤더를 AAD로 바인딩 — 파라미터 downgrade 불가 |
| 저장 범위 | 발급자·계정명·시크릿 전부 암호문 안. 평문 헤더에는 KDF 파라미터만 |
| 메모리 | 마스터 키와 디코딩된 시크릿은 `Zeroize`로 소거 |
| IPC 경계 | 시크릿은 프런트엔드로 넘어가지 않음 (명시적 "시크릿 보기" / 평문 내보내기 제외) |
| 기기 기억 | 파생된 키를 Windows 자격 증명 관리자 / macOS 키체인에 위임 (선택) |

볼트 파일 위치: `%APPDATA%\dev.authom.desktop\vault.json` (Windows),
`~/Library/Application Support/dev.authom.desktop/vault.json` (macOS).
저장은 임시 파일 → rename 방식이며 직전 세대를 `vault.json.bak`으로 남깁니다.

### 반드시 알아야 할 두 가지

1. **마스터 비밀번호를 잃으면 복구 수단이 없습니다.** 설계상 백도어가 없습니다.
2. **각 서비스의 백업/복구 코드는 이 앱 밖에 따로 보관하세요.** 볼트 파일 하나가
   모든 계정이므로, 파일과 비밀번호를 동시에 잃으면 모든 계정에서 잠깁니다.

## 실행

빌드된 실행 파일은 `src-tauri/target/release/authom.exe` 하나로 완결됩니다(약 4 MB).
설치 없이 원하는 위치에 두고 실행하면 되고, 볼트는 사용자 AppData에 따로 저장되므로
exe를 옮겨도 데이터는 유지됩니다.

## 개발

```bash
npm install
npm run app          # 개발 모드 (Vite + Tauri)
npm run app:build    # 설치본 빌드 (Windows: NSIS, macOS: dmg)
```

> **NSIS 인스톨러 빌드 주의**
> `npm run app:build`는 exe를 만든 뒤 NSIS 툴체인을 `%LOCALAPPDATA%\tauri`에 내려받습니다.
> 이 경로가 MSIX/앱 컨테이너로 가상화된 환경에서 실행하면 툴체인 압축 해제 단계가
> `os error 17`로 실패합니다. 이 경우 exe 자체는 정상 생성되어 있으므로 그대로 쓰거나,
> 일반 PowerShell/명령 프롬프트에서 다시 빌드하세요.

Rust 테스트:

```bash
cd src-tauri && cargo test --lib
```

RFC 4226 Appendix D, RFC 6238 Appendix B의 공식 테스트 벡터를 포함해 52개 테스트가 있습니다.

### 요구 사항

- Node.js 20+
- Rust 1.82+
- Windows: MSVC 빌드 도구, WebView2 런타임 (Windows 11 기본 포함)
- macOS: Xcode Command Line Tools

## 구조

```
src/                   React UI
  api.ts               Tauri 커맨드 래퍼
  components/          화면 및 다이얼로그
src-tauri/src/
  otp.rs               HOTP/TOTP/Steam, base32
  crypto.rs            Argon2id + XChaCha20-Poly1305
  vault.rs             볼트 모델 및 파일 포맷
  uri.rs               otpauth:// 파싱/생성
  migration.rs         Google Authenticator protobuf 파서
  qr.rs                QR 디코딩 (파일/클립보드/화면)
  keychain.rs          OS 자격 증명 저장소
  backup.rs            백업 내보내기/가져오기
  state.rs             볼트 상태, 자동 잠금
  commands.rs          IPC 커맨드
```

## 알려진 제약

- macOS에서 **화면 QR 스캔**은 화면 기록 권한이 필요합니다. 최초 실행 시 OS가 묻습니다.
- 코드가 계속 거부되면 대개 **기기 시계 오차**입니다. OS의 시간 자동 동기화를 확인하세요.
- Google Authenticator 내보내기가 QR 여러 장으로 나뉜 경우, 각 QR을 차례로 스캔해야 합니다.
- Tauri 웹뷰는 `window.confirm` / `window.prompt`를 무시합니다. 삭제 확인, 백업 비밀번호
  입력 등은 모두 앱 내부 모달로 구현되어 있으니, 새 기능을 추가할 때 브라우저 기본
  다이얼로그를 쓰지 마세요.
