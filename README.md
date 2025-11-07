# Docker_X3DH
An implementation of the X3DH Key Agreement Protocol with Docker containers

## Specifications
Host's specifications:
- OS: macOS 26.0.1
- Architecture: arm64
- CPU : Apple M2 (8 core)
- RAM : 8 GB
- Docker Desktop: 4.50.0
    - Docker version: 28.5.1
    - Docker compose: 2.40.3

Containers's specifications:
- OS: GNU/Linux Debian 13.1
- gcc: 14.2.0
- Make: 4.4.1
- cmake: 3.31.6
- libsodium: 1.0.20
- libxeddsa: 2.0.1
- Python: 3.12.12
- Flask: 3.1.2
- SQLite: 3.46.1

## How to build it
Do not use `sudo` for the following commands if your user has permissions to run Docker commands.

```bash
git clone https://github.com/mastronardo/Docker_X3DH.git
cd Docker_X3DH
chmod +x sart_service.sh
chmod +x stop_service.sh
chmod +x down_service.sh
```

```bash
# Pull the base images
sudo docker pull debian:trixie-slim
sudo docker pull python:3.12.12-slim-trixie
```

## How to use it
```bash
# Build all the containers and start the service.
# Wait until the service is fully started.
./sart_service.sh
```

```bash
# X3DH Protocol
sudo docker-compose exec alice /app/alice register
sudo docker-compose exec bob /app/bob register
sudo docker-compose exec -it alice /app/alice init_message bob
sudo docker-compose exec bob /app/bob read_init
```

```bash
# Post-X3DH

# From Alice to Bob
sudo docker-compose exec -it alice /app/alice send bob
sudo docker-compose exec bob /app/bob read alice

# From Bob to Alice
sudo docker-compose exec -it bob /app/bob send alice
sudo docker-compose exec alice /app/alice read bob
```

```bash
# To stop the service
./stop_service.sh
```

```bash
# To stop and delete containers, networks and volumes
./down_service.sh
```
