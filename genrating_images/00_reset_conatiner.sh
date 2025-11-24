#!/bin/bash
set -e

echo "--- 0. CLEANUP ---"
sudo containerlab destroy --topo ../dmz-project-sun.clab.yml --cleanup || true
sudo docker rm -f $(sudo docker ps -a -q --filter "label=containerlab=dmz-project-sun") 2>/dev/null || true
sudo docker network prune -f >/dev/null 2>&1
