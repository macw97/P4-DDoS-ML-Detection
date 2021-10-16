import influxdb 
import sys

QUERY_TIME_AGGREGATION = """select * from net order by time desc limit 1"""
QUERY = """select count(length) as num_of_packet,mean(length) as size_of_data from net where time <= '' group by time(3s) order by time desc limit 10"""

database = influxdb.InfluxDBClient('127.0.0.1',8086,'telegraf','telegraf','ddos_base')
measurement_class = sys.argv[1]
out_file = open("DDoS_data_{}.csv".format(measurement_class),"w+")
db_time = None
for measurement in database.query(QUERY_TIME_AGGREGATION).get_points(measurement = 'net'):
    db_time = measurement['time']
    
timestamp = "'"+db_time+"'"
QUERY = QUERY.replace("''",timestamp)

for measurement in database.query(QUERY).get_points(measurement = 'net'):
    print("Measurement - {}".format(measurement))
    cnt = measurement["num_of_packet"]
    meanlen = measurement["size_of_data"]
    out_file.write("{}, {}, {}\n".format(cnt,meanlen,measurement_class))

out_file.close()
print("Finished generating a class {} training dataset!".format(measurement_class))
