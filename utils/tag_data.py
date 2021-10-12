import influxdb 
import sys

QUERY = """select count(length) as a,mean(length) as b from net where time <= 1630017751155236000 group by time(3s) order by time desc limit 5"""

database = influxdb.InfluxDBClient('127.0.0.1',8086,'telegraf','telegraf','ddos_base')
measurement_class = sys.argv[1]
out_file = open("../DDoS_data_{}.csv".format(measurement_class),"w+")


for measurement in database.query(QUERY).get_points(measurement = 'net'):
    cnt = measurement["a"]
    meanlen = measurement["b"]
    out_file.write("{}, {}, {}\n".format(cnt,meanlen,measurement_class))

out_file.close()
print("Finished generating a class {} training dataset!".format(measurement_class))