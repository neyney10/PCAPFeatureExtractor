run:
	python3 cli.py --input tests/pcaps/dns_1.pcap --output temp

tests1:
	python3 tests/test_3rd_party_cisco_joy.py
	python3 tests/test_3rd_party_tshark_tls.py
	python3 tests/test_plugins.py
