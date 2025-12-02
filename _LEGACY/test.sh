sudo docker run -d --name skydive \
  --privileged \
  --pid=host \
  --net=host \
  -p 8082:8082 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e SKYDIVE_ANALYZER_LISTEN=0.0.0.0:8082 \
  -e SKYDIVE_AGENT_TOPOLOGY_PROBES="docker netns netlink" \
  skydive/skydive:latest allinone