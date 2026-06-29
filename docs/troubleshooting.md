# 문제 해결 가이드

## 1. Docker가 실행되지 않을 때

- Docker Desktop 또는 Docker Engine이 켜져 있는지 확인한다.
- `docker version` 명령이 성공하는지 확인한다.

## 2. Elasticsearch가 안 켜질 때

- `docker compose ps`
- `docker compose logs elasticsearch`
- Docker 메모리가 부족하면 메모리를 늘린다.
- 9200 포트를 이미 다른 프로세스가 사용 중인지 확인한다.

## 3. Kibana가 안 열릴 때

- Elasticsearch healthcheck가 끝났는지 확인한다.
- `docker compose logs kibana`
- 첫 기동은 시간이 걸릴 수 있다.

## 4. 9200 연결 실패

- `http://localhost:9200` 접속이 가능한지 확인한다.
- `.env` 또는 환경 변수의 `ELASTICSEARCH_URL` 값이 맞는지 확인한다.
- 운영 환경에서는 9200을 외부 공개하지 않는다.

## 5. 5601 접속 보안

- 로컬 데모에서는 `http://localhost:5601`로 접속한다.
- 운영 환경에서는 5601을 외부에 그대로 공개하지 말고 접근 제한을 둬야 한다.

## 6. raw log가 안 들어올 때

- `python scripts/create_indices.py`를 먼저 실행했는지 확인한다.
- `python scripts/seed_raw_logs.py` 출력에서 `inserted`, `skipped` 값을 확인한다.
- 같은 샘플을 다시 넣으면 `skipped`가 늘어나는 것이 정상이다.

## 7. security event가 생성되지 않을 때

- `python scripts/run_analyzer_once.py` 결과를 확인한다.
- raw log가 이미 `processed=true`인지 확인한다.
- `rules/detection_rules.yml` 경로가 올바른지 확인한다.

## 8. pytest가 실패할 때

- `python -m pip install -r requirements.txt`
- `python -m pytest -q`
- 다른 Python 인터프리터를 쓰고 있지 않은지 확인한다.

## 9. Docker 볼륨 초기화

```bash
docker compose down -v
docker compose up -d
```

또는:

```bash
make clean
make up
```
