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
sudo python3 receiver.py s1
```
In terminal no.3
```bash
sudo telegraf --debug
```
In terminal no.4
```bash
sudo influx -username telegraf -password telegraf
use ddos_base
```
### Part 2 - collecting and training

In terminal with mininet opened - terminal no.1
```bash
h2 ping h1
h3 ping h1
```
In terminal no.2 we should see sniffed packets. We can CTRL+C receiver on termina no.2 and check database
on terminal no.4
```bash
SHOW MEASUREMENTS ON ddos_base
```
If name - net didn't show up that means that probably something wrong happened with parsing so let's check
```bash
SHOW FIELD KEYS ON ddos_base
``` 
shouldn't show our fields parsed
if measurement - net exists we can check database
```bash
SELECT * FROM net
```

To see normal format of time in influxdb CLI use
```bash
precision rfc3339
```

