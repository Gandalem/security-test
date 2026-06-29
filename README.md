# cloud-security-dashboard

본 프로젝트는 상용 SIEM을 대체하기 위한 시스템이 아니라, 클라우드 환경에서 발생하는 다양한 로그가 수집, 정규화, 태깅, 탐지, 시각화되는 전 과정을 직접 구현하여 보안관제의 핵심 원리를 학습하고 설명할 수 있도록 한 교육형·경량형 보안관제 대시보드 시스템이다.

이 저장소는 Wazuh, ModSecurity, Flask 대시보드, React 대시보드, 머신러닝 탐지로 범위를 넓히지 않는다. 핵심 흐름은 `Filebeat 또는 샘플 로그 -> raw-logs-* -> Python 분석 엔진 -> security-events-* -> Kibana` 이다.

## 1. 프로젝트 목적

- 서로 다른 로그 형식을 하나의 파이프라인에서 처리한다.
- raw log가 어떤 과정을 거쳐 security event로 바뀌는지 코드로 설명할 수 있게 만든다.
- 탐지 사유와 대응 권고를 함께 저장해 초보자도 Kibana에서 결과를 이해할 수 있게 한다.
- 상용 SIEM의 기능을 흉내 내는 것이 아니라, 보안관제의 핵심 원리를 실습하는 데 집중한다.

## 2. 차별점

이 프로젝트의 차별점은 성능 주장이 아니다.

- 상용 SIEM보다 성능이 우수하다고 주장하지 않는다.
- 차별점은 로그가 보안 이벤트로 변환되는 과정을 직접 구현하고 설명 가능하게 만든 점이다.
- 기존 수동 로그 확인 방식보다 개선된 점은 로그 정규화, 자동 탐지, 위험도 분류, 탐지 사유, 대응 권고, Kibana 시각화다.
- 초보자와 학생이 보안관제 흐름을 학습하기 쉬운 교육형 구조다.

교수님 질문 대응 포인트:

- "왜 이 프로젝트가 의미가 있나?"  
  사람이 파일을 하나씩 열어 보던 과정을 코드 파이프라인으로 구조화했다.
- "상용 솔루션과 무엇이 다른가?"  
  상용 기능 경쟁이 아니라, 파싱·정규화·탐지·시각화 전 과정을 직접 구현해 설명 가능성을 높였다.
- "학습용으로 어떤 점이 좋은가?"  
  탐지 결과마다 `detection_reason`, `recommendation`, 일부 MITRE 필드가 포함되어 결과 해석이 쉽다.

## 3. 아키텍처

자세한 문서는 [docs/architecture.md](/D:/security/docs/architecture.md)에 있다.

1. 샘플 로그 또는 Filebeat가 로그를 수집한다.
2. `scripts/seed_raw_logs.py`가 raw log를 `raw-logs-demo` 인덱스에 저장한다.
3. `scripts/run_analyzer_once.py`가 미처리 raw log를 조회한다.
4. `parser -> normalizer -> tagger -> detector -> storage` 순서로 처리한다.
5. 탐지 결과를 `security-events-demo` 또는 `security-events-YYYY.MM.DD`에 저장한다.
6. Kibana에서 `security-events-*` Data View를 생성해 이벤트를 확인한다.

## 4. 폴더 구조

```text
cloud-security-dashboard/
├── README.md
├── requirements.txt
├── docker-compose.yml
├── Makefile
├── .env.example
├── src/cloud_security_dashboard/
├── rules/
├── sample_logs/
├── filebeat/
├── scripts/
├── tests/
├── docs/
└── infra/
```

## 5. 실행 요구사항

- Python 3.10 이상
- Docker / Docker Compose
- 첫 실행 시 Docker 이미지 다운로드가 가능한 네트워크 환경

권장:

- Linux, macOS, WSL, Git Bash 등 `make` 사용이 가능한 환경
- Windows PowerShell에서도 `python ...` 명령으로 직접 실행 가능

## 6. 설치 방법

```bash
python -m pip install -r requirements.txt
```

또는:

```bash
make install
```

## 7. Docker 실행 방법

```bash
docker compose up -d
```

또는:

```bash
make up
```

접속 주소:

- Elasticsearch: `http://localhost:9200`
- Kibana: `http://localhost:5601`

중요 보안 주의사항:

- 현재 Compose 설정은 로컬 실습 편의를 위해 `xpack.security.enabled=false`를 사용한다.
- 운영 환경에서는 이 설정을 사용하면 안 된다.
- `9200` 포트는 운영 환경에서 외부 공개하면 안 된다.
- `5601` 포트 역시 외부에 그대로 공개하지 말고 접근 제어가 필요하다.
- 운영 환경에서는 보안 그룹, 방화벽, 인증, HTTPS, 관리자 접근 제한을 반드시 구성해야 한다.

## 8. 실행 순서

### 8-1. 인덱스 템플릿 생성

```bash
python scripts/create_indices.py
```

### 8-2. 샘플 raw log 적재

```bash
python scripts/seed_raw_logs.py
```

### 8-3. 분석 1회 실행

```bash
python scripts/run_analyzer_once.py
```

### 8-4. 결과 요약 확인

```bash
python scripts/generate_demo_report.py
```

한 번에 실행:

```bash
make demo
```

## 9. 예상 실행 흐름

1. `docker compose up -d`
2. `python scripts/create_indices.py`
3. `python scripts/seed_raw_logs.py`
4. `python scripts/run_analyzer_once.py`
5. Kibana에서 `security-events-*` 확인

동일한 `seed_raw_logs.py`를 여러 번 실행해도 raw log는 같은 `raw_id` 기준으로 무한 중복되지 않는다.  
동일한 raw log가 다시 분석되더라도 security event는 같은 `event_id` 기준으로 중복 저장되지 않도록 처리했다.

## 10. Kibana Data View 생성 방법

상세 문서는 [docs/kibana_dashboard_guide.md](/D:/security/docs/kibana_dashboard_guide.md)에 있다.

요약:

1. `http://localhost:5601` 접속
2. `Stack Management -> Data Views`
3. Data View 이름 또는 패턴: `security-events-*`
4. 시간 필드: `@timestamp`
5. `Discover`에서 이벤트 조회
6. `Dashboard`에서 추이/위험도/이벤트 유형/Top IP/상세 테이블 구성

## 11. Dashboard 구성 권장안

- 시간대별 이벤트 추이
- 위험도별 이벤트 분포
- 이벤트 유형별 분포
- Top Source IP
- 최근 보안 이벤트 상세 테이블
- `detection_reason`, `recommendation` 표시

## 12. 핵심 탐지 룰

룰 정의 파일: [rules/detection_rules.yml](/D:/security/rules/detection_rules.yml)

- `BRUTE_FORCE`: 5분 이내 동일 IP의 SSH 로그인 실패 5회 이상
- `ADMIN_PAGE_SCAN`: `/admin`, `/wp-login.php`, `/manager`, `/phpmyadmin` 접근
- `SQL_INJECTION`: SQL Injection 의심 패턴 포함
- `XSS_ATTACK`: XSS 의심 패턴 포함
- `PATH_TRAVERSAL`: `../`, `..%2f`, `/etc/passwd`, `win.ini` 포함
- `SUSPICIOUS_STATUS_SCAN`: 동일 IP의 401/403/404 응답 반복
- `SSH_SUCCESS_AFTER_FAILURE`: 같은 IP에서 실패 반복 후 성공 로그인
- `APP_ERROR_SPIKE`: 짧은 시간 내 앱 ERROR 로그 반복

## 13. security-events 주요 필드

- `@timestamp`
- `event_time`
- `host_name`
- `source_ip`
- `source_port`
- `log_type`
- `service_name`
- `event_type`
- `severity`
- `attack_category`
- `tags`
- `detection_reason`
- `recommendation`
- `raw_message`
- `raw_index`
- `raw_id`
- `rule_id`

## 14. Filebeat 사용 방법

- Filebeat는 선택 사항이다.
- 기본 데모는 `scripts/seed_raw_logs.py`만으로 실행 가능하다.
- 예시 설정은 [filebeat/filebeat.yml](/D:/security/filebeat/filebeat.yml)에 있다.
- 실제 서버 로그를 붙일 때도 중심 구조는 raw log 적재 후 Python 분석 엔진이 처리하는 방식으로 유지한다.

## 15. 테스트

```bash
python -m pytest -q
```

또는:

```bash
make test
```

현재 테스트 범위:

- SSH 실패 로그 파싱
- Nginx access log 파싱
- 공통 필드 정규화
- SQL Injection 탐지
- XSS 탐지
- Path Traversal 탐지
- Admin Page Scan 탐지
- Brute Force 탐지
- SecurityEvent dict 변환
- Analyzer의 raw log 처리 완료 표시와 필드 전달

## 16. 문제 해결

[docs/troubleshooting.md](/D:/security/docs/troubleshooting.md)를 참고한다.

## 17. 보안 주의사항

- 실제 `.env`는 커밋하지 않는다.
- 저장소에는 `.env.example`만 포함한다.
- 실제 클라우드 계정, 실제 API Key, 실제 SSH Key를 요구하지 않는다.
- `infra/`는 과금이 발생하지 않는 스켈레톤 문서 수준만 유지한다.
- 운영 보안 시스템으로 바로 사용하기보다 학습용 구조로 이해해야 한다.

## 18. 발표 시연 순서

1. 프로젝트 목적 설명
2. `docker compose up -d`로 Elasticsearch/Kibana 실행
3. `python scripts/create_indices.py`
4. `python scripts/seed_raw_logs.py`
5. `python scripts/run_analyzer_once.py`
6. `python scripts/generate_demo_report.py`
7. Kibana Discover에서 `security-events-*` 확인
8. `detection_reason`, `recommendation`, `severity`를 기준으로 탐지 사유 설명

## 19. 향후 개선 계획

- 더 많은 로그 형식 지원
- Filebeat 연동 가이드 보강
- 일자별 인덱스 전략 문서화
- 이벤트 상관 분석 룰 추가
