from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from p4utils.utils.helper import load_topo
import influxdb, time, signal
from sklearn.ensemble import RandomForestClassifier
import re
import sys
import pandas as pd

QUERY_ENTROPY = """select * from ddos_e order by time desc limit 3"""
ddos = {
        "entropy": ("ddos_entropy", "ddos_e", QUERY_ENTROPY)
}
"""
TODO:
1. Check if packet mirroring after p4runtime controller start works
2. Deactivate deleting entries in lookup tables after ddos attack recognition
3. Correct learning process - use SVM and RandomForest
4. Slice datasets to learning and testing in 80/20 ratio
5. Test working on real network 
6. Fix concatenate of arrays when reading csv
"""

blockip=[]

training_dataset = ["./DDoS_data_0.csv", "./DDoS_data_1.csv"]

def ip_check(ip_address): 
        if re.match(r'([0-9]+\.){3}[0-9]+\/[0-9]+',ip_address):
                return ip_address
        return '0.0.0.0/24'

def mac_check(mac_address):
        if re.match(r'([a-f0-9]{2}\:){5}[a-f0-9]{2}',mac_address):
                return mac_address
        return '00:00:00:00:00:00'


class myController(object):

    def __init__(self):
        self.topo = load_topo('topology.json')
        self.controllers = {}
        self.controllers_thrift = {}
        self.connect_to_switches()

    def handle_mirroring(self, switch, line):
        params = line.split()
        
        try: 
           mirroring_id = params[1]
           egress_spec = params[2]
        except IndexError as e:
                print("not enough data for mirroring session add: {}".format(e))
        
        self.controllers_thrift[switch].mirroring_add(int(mirroring_id), int(egress_spec))


    def setup_switch(self, switch):
        print("============== P4Runtime switch setup ================")
        print("{} switch setup: ".format(switch))

        table = open("topology/{}-runtime_command.txt".format(switch),"r")
        self.controllers[switch].table_set_default('ipv4_lpm','drop')
        
        for line in table.readlines():
                if re.match(r'^table_set_default', line):
                        continue

                if re.match(r'^mirroring_add', line):
                        self.handle_mirroring(switch, line)
                        continue

                params = line.split()
        
                try: 
                        ip = params[3]
                        mac = params[5]
                        port = params[6]
                except IndexError as e:
                        print("Uncorrect format of table to add in switch {}".format(switch))
                        
                print("Adding table entry:\n{} {} {}".format(ip_check(ip), mac_check(mac), port))
                self.controllers[switch].table_add('ipv4_lpm', 'ipv4_forward', [str(ip_check(ip))], [str(mac_check(mac)), str(port)])
                

    def connect_to_switches(self):
        
        for p4switch in self.topo.get_p4switches():
            print("P4 switch - {}".format(p4switch))
            thrift_port = self.topo.get_thrift_port(p4switch)
            id = self.topo.get_p4switch_id(p4switch)
            grpc = self.topo.get_grpc_port(p4switch)
            self.controllers_thrift[p4switch] = SimpleSwitchThriftAPI(thrift_port)
            self.controllers[p4switch] = SimpleSwitchP4RuntimeAPI(device_id = id,
                                                                  grpc_port = grpc,
                                                                  p4rt_path = "main_p4rt.txt",
                                                                  json_path = "main.json")
            
            self.controllers[p4switch].reset_state()
            self.controllers_thrift[p4switch].reset_state()   
            self.setup_switch(p4switch)                             

        

class gar_py:
        def __init__(self, db_host = 'localhost', port = 8086, db = 'ddos_base', kern_type = 'linear', dbg = False, measurement_name = None, query = None):
                self.debug = dbg
                self.host = db_host
                self.port = port
                self.dbname = db
                self.client = influxdb.InfluxDBClient(self.host, self.port, 'telegraf', 'telegraf', self.dbname)
                self.forest = RandomForestClassifier(criterion = "gini", max_depth = 5, random_state = True)
                self.training_files = training_dataset
                self.measurement_name = measurement_name
                self.query = query
                self.controller=myController()
                self.train_svm()
        

        def train_svm(self):
                X = None
                Y = None 
                X2 = None 
                Y2 = None
                for fname in self.training_files:
                        data = pd.read_csv(fname)
                        if X is None and Y is None:
                                X = data.iloc[:,:-1]
                                Y = data.iloc[:,-1]
                        else:
                                X2 = data.iloc[:,:-1]
                                Y2 = data.iloc[:,-1]

                features = X.append(X2)
                labels = Y.append(Y2)
                print("FEATURES :\n {}".format(features))
                print("LABELS :\n {}".format(labels))
                self.forest.fit(features, labels)

        def work_time(self):
                last_entry_time = "0"
                while True:
                        entries = list(self.get_data(self.query).get_points(measurement = self.measurement_name))
                        for new_entry in sorted(entries, key = lambda item: item['time']):
                                print("Entry - {}".format(new_entry))
                                print("Old time - {}".format(last_entry_time))
                                if new_entry['time'] >= last_entry_time:
                                        last_entry_time = new_entry['time']
                                        if self.debug:
                                                print("\n** New entry **\ninfo: {}".format(new_entry))
                                        
                                        X_sample = [
                                                new_entry['total_packets'],
                                                new_entry['tcp_packets'],
                                                new_entry['tcp_syn_packets'],
                                                new_entry['udp_packets'],
                                                new_entry['icmp_packets'],
                                                new_entry['avg_len'],
                                                new_entry['entropy'],
                                                new_entry['entropy_port']
                                        ]
                                        self.ring_the_alarm(self.under_attack([X_sample]))
                        time.sleep(3)

        def under_attack(self,arg):
                if self.debug:
                        print("\tCurrent prediction: " + str(self.forest.predict(arg)))
                if self.forest.predict(arg)[0] == 1: 
                        return True
                else:
                        return False

        def get_data(self, petition):
                return self.client.query(petition)

        def ring_the_alarm(self, should_i_ring):
                if should_i_ring:
                        print("ring_the_alarm")
                        

 

def ctrl_c_handler(s, f):
        print("\b\bShutting down MR. SVM... Bye!")
        exit(0)

       

if __name__ == "__main__":
        signal.signal(signal.SIGINT, ctrl_c_handler)
        
        try:
            base = sys.argv[1]
        except IndexError as e:
            print("Pick type of ddos database(entropy,metric,base): {}".format(e))

        if base in ddos:
                db_name, db_measure, db_query = ddos[base]
                ai_bot = gar_py(
                        db_host = '127.0.0.1',
                        db = db_name, 
                        dbg = True, 
                        measurement_name = db_measure, 
                        query = db_query)
                ai_bot.work_time()