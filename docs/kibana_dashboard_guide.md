# Kibana 대시보드 가이드

## 1. Data View 생성

1. Kibana 접속: `http://localhost:5601`
2. 왼쪽 메뉴에서 `Stack Management`
3. `Data Views` 선택
4. `Create data view` 클릭
5. Name 또는 Index pattern에 `security-events-*` 입력
6. Time field는 `@timestamp` 선택
7. 저장

## 2. Discover에서 이벤트 확인

1. 왼쪽 메뉴에서 `Discover`
2. Data View로 `security-events-*` 선택
3. 다음 필드를 추가한다.
   - `@timestamp`
   - `event_time`
   - `event_type`
   - `severity`
   - `attack_category`
   - `source_ip`
   - `log_type`
   - `service_name`
   - `detection_reason`
   - `recommendation`
   - `raw_index`
   - `raw_id`
   - `rule_id`
   - `raw_message`

## 3. 추천 Dashboard 패널

### 시간대별 이벤트 추이

- 시각화: Line chart
- X축: `@timestamp`
- Y축: Count
- Breakdown: `severity`

### 위험도 분포

- 시각화: Pie chart 또는 Donut chart
- Dimension: `severity`
- Metric: Count

### 이벤트 유형 분포

- 시각화: Bar chart
- X축: `event_type`
- Y축: Count

### Top Source IP

- 시각화: Horizontal bar chart
- X축: Count
- Y축: `source_ip`

### 최근 보안 이벤트 상세 테이블

- 시각화: Data table
- 컬럼:
  - `@timestamp`
  - `event_type`
  - `severity`
  - `source_ip`
  - `log_type`
  - `detection_reason`
  - `recommendation`
  - `raw_index`
  - `raw_id`
  - `rule_id`

## 4. 추천 필터

- `severity: HIGH`
- `event_type: BRUTE_FORCE`
- `tags: attack`
- `log_type: web`

## 5. 발표용 설명 포인트

- `detection_reason`은 왜 탐지되었는지 설명한다.
- `recommendation`은 대응 방향을 제시한다.
- `raw_index`, `raw_id`, `rule_id`를 같이 보면 원본 로그와 탐지 규칙 추적이 쉽다.
- 초보자도 Kibana에서 결과를 바로 읽고 설명할 수 있다.
