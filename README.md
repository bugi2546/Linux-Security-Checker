# Linux Server Security Checker

KISA **주요정보통신기반시설 기술적 취약점 분석·평가 가이드라인**을 기반으로 리눅스(Ubuntu) 서버의 계정 관리 보안 항목을 자동 진단하는 Bash 스크립트입니다.
진단 결과를 터미널에 색상으로 보여주고, 서버 IP와 시각이 담긴 리포트 파일로 남깁니다.

---

## 주요 기능

- **자동 진단** — `check.sh` 한 번 실행으로 계정 보안 항목 5가지를 수 초 안에 점검
- **색상 출력** — `[양호]`는 초록색, `[취약]`은 빨간색으로 표시
- **조치 가이드** — 취약 항목마다 원인 설명과 수정 방법을 함께 출력
- **증적 리포트** — `Result_<서버IP>_<YYYYMMDD_HHMMSS>.txt` 파일 자동 생성

## 진단 항목

| 코드 | 항목 | 점검 대상 | 양호 기준 |
|------|------|-----------|-----------|
| U-01 | root 계정 원격 접속 제한 | `/etc/ssh/sshd_config` | `PermitRootLogin no` |
| U-02 | 패스워드 복잡성 설정 | `/etc/pam.d/common-password` | `pam_pwquality.so` / `pam_unix.so`에 `minlen` 설정 |
| U-03 | 계정 잠금 임계값 설정 | `/etc/pam.d/common-auth` | `pam_faillock.so` 또는 `pam_tally` 적용 |
| U-04 | 패스워드 파일 보호 | `/etc/passwd` | 모든 계정이 섀도우 패스워드(`x`) 사용 |
| U-05 | 패스워드 최소 길이 제한 | `/etc/login.defs` | `PASS_MIN_LEN` 8 이상 |

## 요구사항

- **OS**: Ubuntu 20.04 LTS / 22.04 LTS 이상 (Debian 계열 PAM 경로 기준)
- **Shell**: Bash
- **패키지**: OpenSSH Server, PAM 모듈 (`libpam-pwquality` 권장)
- **권한**: 진단은 일반 권한으로도 가능하며, 취약 항목 조치(설정 파일 수정)에는 `sudo` 권한이 필요합니다.

## 사용 방법

```bash
git clone https://github.com/bugi2546/Linux-Security-Checker.git
cd Linux-Security-Checker
chmod +x check.sh
./check.sh
```

## 출력 예시

```
=================================================
        인프라 보안 취약점 진단 리포트
=================================================
진단 대상 IP : 192.168.0.10
진단 일시    : 2026-05-31 17:45:12
=================================================

[U-01] root 계정 원격 접속 제한 점검 결과: [양호]
  -> 취약점 설명: root 계정의 원격 접속이 차단되어 안전합니다.

[U-03] 계정 잠금 임계값 설정 점검 결과: [취약]
  -> 취약점 설명: 로그인 실패 임계값이 없어 비밀번호 무차별 대입 공격에 취약합니다.
  -> 조치 가이드: /etc/pam.d/common-auth 파일에 'pam_faillock.so' 설정을 추가하세요.
...
📢 진단 결과가 파일로 저장되었습니다: Result_192.168.0.10_20260531_174512.txt
```

## 조치 시 주의사항

PAM 설정(`common-auth`, `common-password`)을 잘못 수정하면 로그인이 불가능해질 수 있습니다.

- 수정 전 원본 파일을 백업하세요. (`sudo cp /etc/pam.d/common-auth /etc/pam.d/common-auth.bak`)
- 수정 중에는 root 터미널 세션을 하나 열어 둔 채로 다른 세션에서 로그인을 테스트하세요.
- 로그인이 막혔다면 GRUB의 리커버리 모드(Single User Mode)로 부팅해 백업 파일을 복원할 수 있습니다.
