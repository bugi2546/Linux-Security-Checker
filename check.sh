#!/bin/bash

# =================================================================
# KISA 주요정보통신기반시설 - 리눅스 서버 보안 진단 스크립트 (화면+파일 통합본)
# =================================================================

# [자동 리포트 파일 정의]
SERVER_IP=$(hostname -I | awk '{print $1}')
LOG_DATE=$(date +%Y%m%d_%H%M%S)
RESULT_FILE="Result_${SERVER_IP}_${LOG_DATE}.txt"

# [리포트 첫 대문 작성]
echo "=================================================" | tee "$RESULT_FILE"
echo "        인프라 보안 취약점 진단 리포트            " | tee -a "$RESULT_FILE"
echo "=================================================" | tee -a "$RESULT_FILE"
echo "진단 대상 IP : $SERVER_IP" | tee -a "$RESULT_FILE"
echo "진단 일시    : $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$RESULT_FILE"
echo "=================================================" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# -----------------------------------------------------------------
# [U-01] root 계정 원격 접속 제한 점검
# -----------------------------------------------------------------
echo -n "[U-01] root 계정 원격 접속 제한 점검 결과: " | tee -a $RESULT_FILE
CHECK_SSH=$(grep -i "PermitRootLogin" /etc/ssh/sshd_config | grep -v "#" 2>/dev/null)

if [[ $CHECK_SSH == *"no"* ]]; then
    echo -e "[\033[32m양호\033[0m]" | tee -a $RESULT_FILE
    echo "  -> 취약점 설명: root 계정의 원격 접속이 차단되어 안전합니다." | tee -a $RESULT_FILE
else
    echo -e "[\033[31m취약\033[0m]" | tee -a $RESULT_FILE
    echo "  -> 취약점 설명: 외부에서 최고 관리자(root) 권한으로 직접 접속이 가능합니다." | tee -a $RESULT_FILE
    echo "  -> 조치 가이드: /etc/ssh/sshd_config 파일에서 'PermitRootLogin no'로 수정하세요." | tee -a $RESULT_FILE
fi
echo "" | tee -a $RESULT_FILE

# -----------------------------------------------------------------
# [U-02] 패스워드 복잡성 설정 점검
# -----------------------------------------------------------------
echo -n "[U-02] 패스워드 복잡성 설정 점검 결과: " | tee -a $RESULT_FILE
PAM_FILE="/etc/pam.d/common-password"
CHECK_PAM=$(grep -i "pam_pwquality.so\|pam_unix.so" $PAM_FILE | grep -v "#" 2>/dev/null)

if [[ $CHECK_PAM == *"minlen"* ]]; then
    echo -e "[\033[32m양호\033[0m]" | tee -a $RESULT_FILE
    echo "  -> 취약점 설명: 패스워드 복잡성 및 최소 길이 설정이 올바르게 적용되어 있습니다." | tee -a $RESULT_FILE
else
    echo -e "[\033[31m취약\033[0m]" | tee -a $RESULT_FILE
    echo "  -> 취약점 설명: 패스워드 복잡성 설정이 누락되어 유추하기 쉬운 비밀번호를 사용할 위험이 있습니다." | tee -a $RESULT_FILE
    echo "  -> 조치 가이드: /etc/pam.d/common-password 파일에 'minlen=8' 설정을 추가하세요." | tee -a $RESULT_FILE
fi
echo "" | tee -a $RESULT_FILE

# -----------------------------------------------------------------
# [U-03] 계정 잠금 임계값 설정 점검
# -----------------------------------------------------------------
echo -n "[U-03] 계정 잠금 임계값 설정 점검 결과: " | tee -a $RESULT_FILE
AUTH_FILE="/etc/pam.d/common-auth"
CHECK_LOCK=$(grep -E "pam_faillock.so|pam_tally" $AUTH_FILE | grep -v "#" 2>/dev/null)

if [ ! -z "$CHECK_LOCK" ]; then
    echo -e "[\033[32m양호\033[0m]" | tee -a $RESULT_FILE
    echo "  -> 취약점 설명: 로그인 실패 시 계정 잠금 임계값이 설정되어 무차별 대입 공격을 방어합니다." | tee -a $RESULT_FILE
else
    echo -e "[\033[31m취약\033[0m]" | tee -a $RESULT_FILE
    echo "  -> 취약점 설명: 로그인 실패 임계값이 없어 비밀번호 무차별 대입 공격에 취약합니다." | tee -a $RESULT_FILE
    echo "  -> 조치 가이드: /etc/pam.d/common-auth 파일에 'pam_faillock.so' 설정을 추가하세요." | tee -a $RESULT_FILE
fi
echo "" | tee -a $RESULT_FILE

# -----------------------------------------------------------------
# [U-04] 패스워드 파일 보호 점검
# -----------------------------------------------------------------
echo -n "[U-04] 패스워드 파일 보호 점검 결과: " | tee -a $RESULT_FILE
CHECK_SHADOW=$(awk -F: '{print $2}' /etc/passwd | grep -v "x" | wc -l)

if [ "$CHECK_SHADOW" -eq 0 ]; then
    echo -e "[\033[32m양호\033[0m]" | tee -a $RESULT_FILE
    echo "  -> 취약점 설명: 모든 계정이 암호화된 섀도우 패스워드 체계를 사용하여 안전합니다." | tee -a $RESULT_FILE
else
    echo -e "[\033[31m취약\033[0m]" | tee -a $RESULT_FILE
    echo "  -> 취약점 설명: 암호화된 비밀번호 해시값이 노출되어 탈취 및 크래킹 위험이 있습니다." | tee -a $RESULT_FILE
    echo "  -> 조치 가이드: 터미널에 'sudo pwconv' 명령어를 실행하여 섀도우 체계로 전환하세요." | tee -a $RESULT_FILE
fi
echo "" | tee -a $RESULT_FILE

# -----------------------------------------------------------------
# [U-05] 패스워드 최소 길이 제한 점검
# -----------------------------------------------------------------
echo -n "[U-05] 패스워드 최소 길이 제한 점검 결과: " | tee -a $RESULT_FILE
LOGIN_DEFS="/etc/login.defs"
MIN_LEN=$(grep "^PASS_MIN_LEN" $LOGIN_DEFS | awk '{print $2}' 2>/dev/null)

if [ ! -z "$MIN_LEN" ] && [ "$MIN_LEN" -ge 8 ]; then
    echo -e "[\033[32m양호\033[0m]" | tee -a $RESULT_FILE
    echo "  -> 취약점 설명: 패스워드 최소 길이가 ${MIN_LEN}자로 제한되어 있어 안전합니다." | tee -a $RESULT_FILE
else
    echo -e "[\033[31m취약\033[0m]" | tee -a $RESULT_FILE
    echo "  -> 취약점 설명: 패스워드 최소 길이 제한이 느슨하여 유추하기 쉬운 암호가 사용될 수 있습니다." | tee -a $RESULT_FILE
    echo "  -> 조치 가이드: /etc/login.defs 파일 맨 아래에 'PASS_MIN_LEN 8' 설정을 추가하세요." | tee -a $RESULT_FILE
fi
echo "" | tee -a $RESULT_FILE

# =================================================================
# 진단 완료 마감
# =================================================================
echo "=================================================" | tee -a $RESULT_FILE
echo "                진단이 완료되었습니다.            " | tee -a $RESULT_FILE
echo "=================================================" | tee -a $RESULT_FILE

echo -e "\n📢 진단 결과가 파일로 저장되었습니다: \033[33m$RESULT_FILE\033[0m"