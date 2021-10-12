TOPO = topology/topology_app.json

BUILD_DIR = build
PCAP_DIR = pcap
LOG_DIR = log

ifndef TOPO
TOPO = topology.json
endif

all: run

run: build
	sudo p4run --config $(TOPO)

build: 
	mkdir -p $(BUILD_DIR)

clean: stop
	rm -f *.pcap
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)
