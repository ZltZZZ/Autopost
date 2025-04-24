# Autopost
Сервис для автоматического публикования постов в социальные сети с автоматической генерацией хештегов.

## Useful Services
Grafana: http://localhost:3000 (логин/пароль по умолчанию: admin/admin)

Prometheus: http://localhost:9090
http://localhost:9090/alerts

cAdvisor: http://localhost:8081

Node Exporter Full (ID: 1860)

Docker and system monitoring (ID: 893)

Blackbox Exporter (ID: 7587)

### RAM Alert Test
docker run --rm -it --name memhog polinux/stress-ng --vm 1 --vm-bytes 4G --timeout 300

### CPU Alert test
docker run --rm -it --name stresser polinux/stress-ng --cpu 2 --timeout 300s 

### NVRAM Alert test
dd if=/dev/zero of=/tmp/disktest bs=1G count=30

