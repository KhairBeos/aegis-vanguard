.PHONY: install run clean setup-wsल2

install:
	pip install -r requirements.txt

run:
	sudo python3 loader.py

run-test:
	sudo python3 loader.py \
		--output /tmp/ebpf-events-test.jsonl \
		--events process_start,network_connect,file_open \
		--log-level DEBUG \
		--throttle-ms 50

run-dev:
	sudo python3 loader.py \
		--output /var/run/aegis/ebpf-events.jsonl \
		--log-level INFO \
		--throttle-ms 100

clean:
	rm -f /tmp/ebpf-events-test.jsonl
	rm -f /var/run/aegis/ebpf-events.jsonl

setup-wsל2:
	@echo "WSL2 Setup Instructions:"
	@echo "1. Enable nested kernel: wsl --update && wsl --list --verbose"
	@echo "2. Install BCC on WSL2: sudo apt-get install linux-headers-\$$(uname -r) bpftrace"
	@echo "3. Create output dir: sudo mkdir -p /var/run/aegis && sudo chmod 755 /var/run/aegis"
	@echo "4. Run loader: make run-dev"
