# AWS 스켈레톤

이 폴더는 실제 과금이 발생하는 배포 코드를 넣기 위한 용도가 아니다.

향후 확장 아이디어:

- EC2에 Elasticsearch/Kibana를 직접 올리는 대신 관리형 서비스 검토
- Security Group으로 5601/9200 접근 제한
- Bastion 또는 VPN 기반 관리자 접근

현재 프로젝트의 핵심 동작은 로컬 Docker Compose 환경이다.
