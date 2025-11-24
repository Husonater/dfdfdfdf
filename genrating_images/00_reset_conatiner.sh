#!/bin/bash
set -e

echo "--- 0. CLEANUP ---"
sudo containerlab destroy --topo ../dmz_topology.yaml --cleanup || true
sudo docker rm -f $(sudo docker ps -a -q --filter "label=containerlab=dmz-project-sun") 2>/dev/null || true
sudo docker network prune -f >/dev/null 2>&1
sudo rm -rf images config waf_logs || true