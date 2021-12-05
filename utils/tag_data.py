import influxdb 
import sys

databases = {
    "entropy" : ("ddos_entropy","ddos_e"),
    "metrics" : ("ddos_metric_base","ddos_m"),
    "normal"  : ("ddos_base","ddos_b")
}

QUERY_TIME_AGGREGATION = """select * from net order by time desc limit 1"""
QUERY_ENTROPY = """select * from ddos_e order by time desc limit 500"""
QUERY_METRICS = """select * from ddos_m order by time desc limit 500"""
QUERY_BASE = """select count(length) as num_of_packet,mean(length) as size_of_data from net where time <= '' group by time(3s) order by time desc limit 10"""

class MetricCollecter:
    def __init__(self, db_host = 'localhost', port = 8086, db = 'telegraf', measure_name = None, measurement_class = None, out_file = None, label = None):
        self.host = db_host
        self.port = port
        self.dbname = db
        self.measure_name = measure_name
        self.measurement_class = measurement_class
        self.out_file = out_file
        self.label = label
        self.client = influxdb.InfluxDBClient(self.host,self.port, 'telegraf', 'telegraf', db)

    def metric_base_aggregate_time(self):
        measurement = self.client.query(QUERY_TIME_AGGREGATION).get_points(measurement = self.measure_name)
        return measurement['time']

    def collect(self,q):
        file = open(self.out_file,"w+")
        for measurement in self.client.query(q).get_points(measurement = self.measure_name):
            total_packets = measurement['total_packets']
            tcp_packets = measurement['tcp_packets']
            tcp_syn_packets = measurement['tcp_syn_packets']
            udp_packets = measurement['udp_packets']
            icmp_packets = measurement['icmp_packets']
            total_length_of_packets = measurement['len_packets']
            entropy_of_src_ip = measurement['entropy']
            entropy_of_src_port = measurement['entropy_port']
            file.write("{}, {}, {}, {}, {}, {}, {}, {}, {}\n".format(
                total_packets,
                tcp_packets,
                tcp_syn_packets,
                udp_packets,
                icmp_packets,
                total_length_of_packets,
                entropy_of_src_ip,
                entropy_of_src_port,
                self.label
            ))
        file.close()

    def collect_metrics(self,q):
        file = open(self.out_file,"w+")
        for measurement in self.client.query(q).get_points(measurement = self.measure_name):
            total_packets = measurement['total_packets']
            tcp_packets = measurement['tcp_packets']
            tcp_syn_packets = measurement['tcp_syn_packets']
            udp_packets = measurement['udp_packets']
            icmp_packets = measurement['icmp_packets']
            file.write("{}, {}, {}, {}, {}, {}\n".format(
                total_packets,
                tcp_packets,
                tcp_syn_packets,
                udp_packets,
                icmp_packets,
                self.label
            ))
        file.close()
            
    def collect_base(self,q):
        file = open(self.out_file,"w+")
        for measurement in self.client.query(q).get_points(measurement = self.measure_name):
            cnt = measurement['num_of_packet']
            mean_len = measurement['size_of_data']
            file.write("{}, {}, {}\n".format(
                cnt,
                mean_len,
                self.label
            ))
        file.close()
        


def actions(database_type,measure):
    global QUERY_BASE
    db_name, measure_n = databases[database_type]
    collector = MetricCollecter(db = db_name,
                                measure_name = measure_n,
                                measurement_class = measure, 
                                out_file = "DDoS_data_{}.csv".format(measure),
                                label = measure)

    if database_type == "entropy":
        collector.collect(QUERY_ENTROPY)
    elif database_type == "metrics":
        collector.collect_metrics(QUERY_METRICS)
    else:
        timestamp = collector.metric_base_aggregate_time()
        time = "'" + timestamp + "'"
        QUERY_BASE = QUERY_BASE.replace("''",time)
        collector.collect_base(QUERY_BASE)
        

if __name__ == "__main__":
    try:
        database = sys.argv[1]
    except IndexError as e:
        print("Database to gather metrics not provided: {}".format(e))

    try:
        measurement_class = sys.argv[2] 
    except IndexError as e:
        print("Measurement class not provided: {}".format(e))

    if database in databases:
        actions(database,measurement_class)
        print("Finished generating a label = {} training dataset!".format(measurement_class))
    else:
        print("Database {} doesn't exist".format(database))
    



