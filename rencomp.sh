#!/bin/bash

docker build -t flask_web ./flask_web
docker build -t flask_pdf ./flask_pdf
docker-compose up
