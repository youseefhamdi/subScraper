# Docker Build Instructions for Mac (Multi-platform)

This guide explains how to build the subScraper Docker container on macOS for multiple platforms.

## Prerequisites

1. **Install Docker Desktop for Mac**
   - Download from: https://www.docker.com/products/docker-desktop
   - Install and start Docker Desktop

2. **Enable BuildKit and Multi-platform Support**
   
   Docker Desktop for Mac includes buildx by default, but you need to create a builder:

   ```bash
   # Create a new builder instance
   docker buildx create --name multiplatform --driver docker-container --use
   
   # Bootstrap the builder
   docker buildx inspect --bootstrap
   ```

## Building the Container

### Option 1: Build for Your Current Platform (Fastest)

If you just want to build for your Mac's architecture:

```bash
# For Apple Silicon Macs (M1/M2/M3)
docker build -t subscraper:latest .

# For Intel Macs
docker build -t subscraper:latest .
```

### Option 2: Build for Multiple Platforms

To build a multi-platform image that works on different architectures:

```bash
# Build for multiple platforms and push to a registry
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -t yourusername/subscraper:latest \
  --push .

# Or build and load for local use (single platform at a time)
docker buildx build --platform linux/amd64 \
  -t subscraper:latest \
  --load .
```

### Option 3: Build for Specific Platform

If you need to build specifically for a different platform:

```bash
# For Linux AMD64 (most cloud servers)
docker buildx build --platform linux/amd64 \
  -t subscraper:amd64 \
  --load .

# For Linux ARM64 (AWS Graviton, Raspberry Pi 4)
docker buildx build --platform linux/arm64 \
  -t subscraper:arm64 \
  --load .

# For Linux ARM v7 (Raspberry Pi 3)
docker buildx build --platform linux/arm/v7 \
  -t subscraper:armv7 \
  --load .
```

## Running the Container

### Basic Run

```bash
docker run -d \
  --name subscraper \
  -p 8342:8342 \
  -v $(pwd)/recon_data:/app/recon_data \
  subscraper:latest
```

### Run with Custom Configuration

```bash
docker run -d \
  --name subscraper \
  -p 8342:8342 \
  -v $(pwd)/recon_data:/app/recon_data \
  -v $(pwd)/wordlists:/app/wordlists \
  -e PYTHONUNBUFFERED=1 \
  subscraper:latest
```

### Run with Interactive Shell

```bash
docker run -it \
  --name subscraper \
  -p 8342:8342 \
  -v $(pwd)/recon_data:/app/recon_data \
  subscraper:latest \
  /bin/bash
```

### Run a One-off Scan

```bash
docker run --rm \
  -v $(pwd)/recon_data:/app/recon_data \
  subscraper:latest \
  python3 main.py example.com --wordlist ./wordlists/common.txt
```

## Accessing the Web Interface

Once the container is running, access the web interface at:
- http://localhost:8342

## Docker Compose (Optional)

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  subscraper:
    build: .
    container_name: subscraper
    ports:
      - "8342:8342"
    volumes:
      - ./recon_data:/app/recon_data
      - ./wordlists:/app/wordlists
    environment:
      - PYTHONUNBUFFERED=1
    restart: unless-stopped
```

Then run:

```bash
docker-compose up -d
```

## Troubleshooting

### Issue: "no matching manifest"

This means the image wasn't built for your platform. Rebuild with:

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t subscraper:latest --load .
```

### Issue: Tools not found

Some tools may fail to install on certain architectures. Check the build logs:

```bash
docker buildx build --platform linux/arm64 -t subscraper:latest --load . --progress=plain
```

### Issue: Permission denied

If you get permission errors with mounted volumes:

```bash
# On Mac, ensure Docker has access to the directory in:
# Docker Desktop -> Settings -> Resources -> File Sharing
```

## Performance Tips

1. **Use BuildKit Cache**: BuildKit caches layers efficiently, making rebuilds faster

2. **Allocate More Resources**: In Docker Desktop settings, increase:
   - CPUs: 4+ cores recommended
   - Memory: 8GB+ recommended

3. **Use .dockerignore**: Create a `.dockerignore` file to exclude unnecessary files:

```
recon_data/
__pycache__/
*.pyc
.git/
.gitignore
```

## Platform-Specific Notes

### Apple Silicon (M1/M2/M3)

- Native ARM64 builds are fastest on Apple Silicon
- Use `--platform linux/arm64` for native builds
- Cross-compilation to AMD64 works but is slower

### Intel Macs

- Native AMD64 builds
- Use `--platform linux/amd64` for native builds
- Can build ARM images but slower due to emulation

## Advanced: Multi-platform Registry Push

To build and push to Docker Hub for all platforms:

```bash
# Login to Docker Hub
docker login

# Build and push multi-platform image
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -t yourusername/subscraper:latest \
  -t yourusername/subscraper:v1.0.0 \
  --push .
```

Then others can pull with:

```bash
docker pull yourusername/subscraper:latest
```

Docker will automatically pull the correct architecture for their system.

## Cleanup

```bash
# Stop and remove container
docker stop subscraper && docker rm subscraper

# Remove image
docker rmi subscraper:latest

# Remove builder
docker buildx rm multiplatform

# Clean up build cache
docker buildx prune -f
```

## Support

For issues or questions:
- GitHub Issues: https://github.com/The-XSS-Rat/subScraper/issues
- Check Docker logs: `docker logs subscraper`
