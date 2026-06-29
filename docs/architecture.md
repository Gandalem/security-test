# 아키텍처 문서

## 1. 시스템 방향성

이 프로젝트는 상용 SIEM 대체가 목적이 아니다.  
교육형·경량형 보안관제 시스템으로서 로그가 수집되고 보안 이벤트로 변환되는 과정을 직접 구현하고 설명하는 데 목적이 있다.

포함하지 않는 범위:

- Wazuh 중심 운영 구조
- ModSecurity / OWASP CRS / WAF 리버스 프록시 구현
- Flask / React 자체 대시보드
- 머신러닝 탐지

핵심 구성:

- Filebeat 또는 샘플 로그
- Elasticsearch `raw-logs-*`
- Python 분석 엔진
- Elasticsearch `security-events-*`
- Kibana

## 2. 전체 데이터 흐름

1. 로그 수집
   - `sample_logs/`의 샘플 로그 또는 Filebeat 입력
2. raw log 저장
   - `scripts/seed_raw_logs.py`
   - 인덱스: `raw-logs-demo`
3. 미처리 raw log 조회
   - `Analyzer.run_once()`
4. 파싱
   - `parser.py`
5. 정규화
   - `normalizer.py`
6. 태깅
   - `tagger.py`
7. 탐지
   - `detector.py`
8. 보안 이벤트 저장
   - `storage.py`
   - 인덱스: `security-events-*`
9. Kibana 시각화
   - Discover / Dashboard

## 3. raw-logs와 security-events를 분리하는 이유

- raw-logs는 원본 보존이 목적이다.
- security-events는 분석 결과와 설명 가능한 탐지 정보를 담는 것이 목적이다.
- 원본과 결과를 분리하면 디버깅과 시연이 쉬워진다.
- `raw_id`, `raw_index`로 원본과 이벤트를 연결할 수 있다.

## 4. Python 분석 엔진 역할

### parser.py

- `auth.log`에서 SSH 로그인 성공/실패, 사용자명, IP, 포트를 추출한다.
- `access.log`에서 IP, 메서드, URL, 쿼리, 상태코드를 추출한다.
- `app.log`에서 timestamp, level, user, ip를 추출한다.
- `syslog`에서 최소 timestamp, host, service, message를 추출한다.
- 파싱 실패 시 `unknown` 유형으로 안전하게 처리한다.

### normalizer.py

- 서로 다른 로그를 공통 필드 구조로 맞춘다.
- 이후 태깅과 탐지가 같은 입력 형식을 사용하도록 만든다.

### tagger.py

- `auth`, `web`, `app`, `attack`, `abnormal` 태그를 붙인다.
- Kibana 필터링이 쉬워진다.

### detector.py

- `rules/detection_rules.yml`에서 탐지 기준을 읽는다.
- 문자열 패턴 탐지와 시간 기반 반복 탐지를 함께 처리한다.
- 모든 이벤트에 `detection_reason`, `recommendation`을 포함한다.

### storage.py

- Elasticsearch index template 생성
- raw log 저장
- security event 저장
- processed 상태 업데이트
- payload 생성 분리

## 5. 설명 가능한 탐지 구조

이 프로젝트는 "탐지됨" 같은 단순 결과를 남기지 않는다.

각 이벤트에는 최소한 다음이 포함된다.

- `event_type`
- `severity`
- `attack_category`
- `detection_reason`
- `recommendation`
- `raw_message`
- `raw_id`
- `raw_index`
- `rule_id`

이 구조 덕분에 Kibana 화면만 보고도 왜 탐지되었는지 설명할 수 있다.
