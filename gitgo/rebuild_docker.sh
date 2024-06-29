#!/bin/bash

IMAGE_NAME=gitgo
PORT=8080

sudo docker ps -q --filter "ancestor=test/$IMAGE_NAME" | xargs -I {} sudo docker stop {}
sudo docker ps -a
sudo docker rmi "test/$IMAGE_NAME"
sudo docker build -t "test/${IMAGE_NAME}" --build-arg port=${PORT} ./deploy
sudo docker run --name ${IMAGE_NAME} -d -p $PORT:$PORT --rm -it test/${IMAGE_NAME}

echo "Rebuild completed, connecting to instance..."
echo ""
sleep 5

firefox localhost:8080
