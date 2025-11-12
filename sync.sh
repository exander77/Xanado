#!/bin/bash
rsync -avz --exclude 'node_modules' ./ pi@10.9.8.249:/home/pi/docker_deployments/Xanado
