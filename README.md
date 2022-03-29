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
## Config

When installing telegraf remember to create copy of original default configuration
```bash
mv /etc/telegraf/telegraf.conf{,.old}
```
when copy is created we can preform hard link creation for configuration. I don't know why but soft didn't work out.
```bash
ln config/telegraf.conf /etc/telegraf/telegraf.conf
```
changing config files we have to perform
```bash
sudo systemctl restart influxdb
sudo systemctl restart telegraf
```
Check if telegraf and influxdb correctly standing by
```bash
sudo systemctl status influxdb
sudo systemctl status telegraf
```


## Workflow

### Part 1 - Setup

In terminal no.1 from repo directory
```bash
make run
```
after setup quick check if everything works fine
```bash
pingall
h3 ping h1
h2 ping h1
```
In terminal no.2 
```bash
sudo python3 utils/receiver.py s1
```
In terminal no.3
```bash
sudo telegraf --debug
```
In terminal no.4
```bash
sudo influx -username telegraf -password telegraf
use ddos_entropy
```
### Part 2 - collecting and training

In topology_app.json field tasks_file can be changed between scenario with normal traffic generation and malicious traffic generation.
Firstly setup network with 
```bash
make run
```

In terminal no.2 activate sniffing script. On terminal no.4 check if metrics are showing up in database
```bash
select from * ddos_e
```
To see normal format of time in influxdb CLI use
```bash
precision rfc3339
```
After traffic was generated 
```bash
sudo python3 utils/tag_data.py 0
```
0 or 1 depends on type of generated traffic.
Next we can start the controller
```bash
sudo python3 utils/controller.py entropy
```

