#!bin/bash

docker-compose down -v
docker build -t custom-superset-v1 .
docker-compose -f docker-compose-non-dev.yml up -d
