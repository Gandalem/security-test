# 발표 시연 시나리오

## 1. 시연 목표

샘플 로그가 raw log로 적재되고, Python 분석 엔진을 거쳐 보안 이벤트로 저장되며, Kibana에서 탐지 사유까지 확인되는 흐름을 보여준다.

## 2. 시연 순서

1. 프로젝트 소개
   - 상용 SIEM 대체가 아니라 교육형·경량형 보안관제 실습 프로젝트임을 설명한다.

2. 인프라 실행
   - `docker compose up -d`
   - Elasticsearch와 Kibana 컨테이너가 올라왔는지 확인한다.

3. 인덱스 템플릿 생성
   - `python scripts/create_indices.py`

4. 샘플 로그 적재
   - `python scripts/seed_raw_logs.py`
   - raw log가 `raw-logs-demo`에 저장됨을 설명한다.

5. 분석 실행
   - `python scripts/run_analyzer_once.py`
   - 미처리 raw log가 파싱, 정규화, 태깅, 탐지를 거쳐 `security-events-*`로 저장됨을 설명한다.

6. 결과 요약 확인
   - `python scripts/generate_demo_report.py`

7. Kibana 확인
   - `security-events-*` Data View 생성
   - Discover에서 이벤트 조회

8. 탐지 사유 설명
   - `BRUTE_FORCE`
   - `SQL_INJECTION`
   - `XSS_ATTACK`
   - `PATH_TRAVERSAL`
   - `ADMIN_PAGE_SCAN`
   - `SUSPICIOUS_STATUS_SCAN`

## 3. 발표 멘트 포인트

- raw log와 security event를 분리해 원본과 결과를 모두 보여줄 수 있다.
- 탐지 이벤트마다 `detection_reason`, `recommendation`이 있어 설명 가능성이 높다.
- 룰 파일을 수정하면 탐지 기준을 쉽게 바꿀 수 있다.
- 상용 제품 기능 경쟁이 아니라, 보안관제 핵심 흐름을 학습하는 데 초점을 맞췄다.
