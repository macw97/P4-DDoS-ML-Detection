# P4-DDoS-ML-Detection
DDoS detection using Machine Learning and P4 language

## Scapy

To install proper scapy which handles sniffing on multiple interfaces not just one we would need to install it from 
github repo because version 2.4.5 installed in pip by command

```bash
pip install scapy==2.4.5
```

should support sniffing on multiple interfaces but eventually it doesn't. It was fixed in 
reported issue - [sniff fails when the iface parameter is a list](https://github.com/secdev/scapy/issues/3232)
To install newest version from github repo

```bash
pip uninstall scapy
pip install git+https://github.com/secdev/scapy.git
```

## Utils

Refactored code for easy compilation and mininet network start. Supported language python3.
Supported language version for utils from [p4lang/tutorials](https://github.com/p4lang/tutorials) is python2.
