#!bin/bash

docker-compose down -v
docker build -t custom-superset-v1 .
docker-compose -f docker-compose-image-tag.yml up -d
