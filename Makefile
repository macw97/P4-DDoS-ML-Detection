TOPO = topology/topology_app.json
DATA_MARKER = utils/tag_data.py
SNIFFER_SCRIPT = utils/receiver.py

BUILD_DIR = build
PCAP_DIR = pcap
LOG_DIR = log

all: run

run: build
	sudo p4run --config $(TOPO)

build: 
	mkdir -p $(BUILD_DIR)

clean: 
	rm -f *.pcap
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

sniff:
	sudo python3 $(SNIFFER_SCRIPT) ${PARAMS}

data_marking:
	python3 ${DATA_MARKER} ${PARAMS}
