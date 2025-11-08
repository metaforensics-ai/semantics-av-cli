# SemanticsAV Docker Deployment

Production-ready containerized deployment with 100% backward compatibility.

## Quick Start

1. **Create API key file:**
```bash
   cd docker
   echo "sav_your_api_key_here" > api-key.txt
```

2. **Build and run:**
```bash
   docker-compose up -d
```

3. **Verify:**
```bash
   docker-compose ps
   docker-compose logs -f semantics-av
   curl http://localhost:9216/api/v1/health
```

## Configuration

### Environment Variables (8 Core Variables)

| Variable | Default | Description |
|----------|---------|-------------|
| `SEMANTICS_AV_API_KEY` | - | API key (use Docker secret instead) |
| `SEMANTICS_AV_LOG_LEVEL` | INFO | DEBUG, INFO, WARN, ERROR |
| `SEMANTICS_AV_HTTP_HOST` | 0.0.0.0 | HTTP API bind address |
| `SEMANTICS_AV_HTTP_PORT` | 9216 | HTTP API port |
| `SEMANTICS_AV_WORKER_THREADS` | 0 | Worker threads (0=auto) |
| `SEMANTICS_AV_AUTO_UPDATE` | true | Auto-update models |
| `SEMANTICS_AV_UPDATE_INTERVAL` | 60 | Update check interval (minutes) |
| `SEMANTICS_AV_NETWORK_TIMEOUT` | 120 | Network timeout (seconds) |

### Security: Docker Secrets (Recommended)

**Production:**
```yaml
services:
  semantics-av:
    secrets:
      - api-key

secrets:
  api-key:
    file: ./api-key.txt
```

**Development:**
```yaml
services:
  semantics-av:
    environment:
      SEMANTICS_AV_API_KEY: sav_dev_key_here
```

## HTTP API Usage

### Health Check
```bash
curl http://localhost:9216/api/v1/health
```

### Scan File
```bash
curl -X POST http://localhost:9216/api/v1/scan \
  -F "file=@suspicious.exe"
```

### Cloud Analysis
```bash
curl -X POST http://localhost:9216/api/v1/analyze \
  -F "file=@malware.exe" \
  -F "language=en"
```

### Update Models
```bash
curl -X POST http://localhost:9216/api/v1/models/update
```

### Get Status
```bash
curl http://localhost:9216/api/v1/status
```

## Production Deployment

### Resource Limits
```yaml
deploy:
  resources:
    limits:
      cpus: '2.0'
      memory: 1G
    reservations:
      cpus: '0.5'
      memory: 256M
```

### High Availability
```yaml
services:
  semantics-av:
    deploy:
      replicas: 3
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
```

### Read-Only Filesystem
```yaml
services:
  semantics-av:
    read_only: true
    tmpfs:
      - /tmp
    volumes:
      - data:/var/lib/semantics-av
```

## Troubleshooting

### View Logs
```bash
docker-compose logs -f semantics-av
docker-compose logs --tail=100 semantics-av
```

### Check Health
```bash
docker-compose ps
docker inspect semantics-av-semantics-av-1 --format='{{.State.Health.Status}}'
```

### Shell Access
```bash
docker-compose exec semantics-av sh
```

### Reset Everything
```bash
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

### Common Issues

**API Key Not Working:**
```bash
docker-compose exec semantics-av sh -c 'ls -l /run/secrets/'
cat api-key.txt
```

**Port Already in Use:**
```yaml
ports:
  - "9217:9216"
```

**Out of Memory:**
```yaml
deploy:
  resources:
    limits:
      memory: 1G
```

## Image Information

**Base Image:** debian:12-slim (glibc compatibility)  
**Expected Size:** 150-200MB  
**User:** semantics-av (UID 1000, non-root)  
**Volumes:** /var/lib/semantics-av (models + data)

### Check Image Size
```bash
docker images semantics-av:latest
```

### Inspect Layers
```bash
docker history semantics-av:latest
```

## Security Features

- ✅ Non-root user (UID 1000)
- ✅ Docker Secrets support
- ✅ Minimal base image (Debian Slim)
- ✅ No shell in CMD
- ✅ Health checks enabled
- ✅ Resource limits configurable
- ✅ Read-only filesystem compatible
- ✅ HTTPS certificate validation

## Monitoring

### Prometheus Metrics (Future)
```yaml
expose:
  - "9090"
```

### Log Aggregation
```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

## Kubernetes Deployment
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: semantics-av-api-key
stringData:
  api-key: sav_your_key_here
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: semantics-av
spec:
  replicas: 2
  selector:
    matchLabels:
      app: semantics-av
  template:
    metadata:
      labels:
        app: semantics-av
    spec:
      containers:
      - name: semantics-av
        image: semantics-av:latest
        ports:
        - containerPort: 9216
        env:
        - name: SEMANTICS_AV_LOG_LEVEL
          value: INFO
        - name: SEMANTICS_AV_WORKER_THREADS
          value: "0"
        volumeMounts:
        - name: api-key
          mountPath: /run/secrets/api-key
          subPath: api-key
          readOnly: true
        - name: data
          mountPath: /var/lib/semantics-av
        livenessProbe:
          httpGet:
            path: /api/v1/health
            port: 9216
          initialDelaySeconds: 10
          periodSeconds: 30
        resources:
          limits:
            cpu: "1"
            memory: 512Mi
          requests:
            cpu: "0.5"
            memory: 256Mi
      volumes:
      - name: api-key
        secret:
          secretName: semantics-av-api-key
      - name: data
        emptyDir: {}
```