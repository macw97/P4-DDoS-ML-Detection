from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from p4utils.utils.helper import load_topo
import p4utils.utils.p4runtime_API
import influxdb, datetime, time, os, signal
from influxdb_client.client.util import date_utils
from dateutil.tz import tzlocal
from sklearn import svm
import argparse
import re
blockip=[]

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

    def setup_switch(self,switch):
        print("============== P4Runtime switch setup ================")
        print("{} switch setup: ".format(switch))

        table = open("topology/{}-runtime_command.txt".format(switch),"r")
        self.controllers[switch].table_set_default('ipv4_lpm','drop')
        for line in table.readlines():
                
                if re.match(r'^table_set_default',line):
                        continue

                params = line.split()

                try: 
                        ip = params[3]
                        mac = params[5]
                        port = params[6]
                except IndexError as e:
                        print("Uncorrect format of table to add in switch {}".format(switch))
                        
                print("Adding table entry:\n{} {} {}".format(ip_check(ip),mac_check(mac),port))
                self.controllers[switch].table_add('ipv4_lpm','ipv4_forward',[str(ip_check(ip))],[str(mac_check(mac)),str(port)])
                

    def switch_table_delete(self,switch):
        print("============== P4Runtime switch table delete ================")
        print("{} switch table entry delete: ".format(switch))
        # in s1 should delete 10.0.3.3 more likely 
        if switch == 's1':
                self.controllers[switch].table_delete_match('ipv4_lpm',['10.0.3.3/24'])
        elif switch == 's3':
                self.controllers[switch].table_delete_match('ipv4_lpm',['10.0.1.1/24'])


    def connect_to_switches(self):
        
        for p4switch in self.topo.get_p4switches():
            print("P4 switch - {}".format(p4switch))
            thrift_port = self.topo.get_thrift_port(p4switch)
            id = self.topo.get_p4switch_id(p4switch)
            grpc = self.topo.get_grpc_port(p4switch)
            self.controllers_thrift[p4switch] = SimpleSwitchThriftAPI(thrift_port)
            self.controllers[p4switch] = SimpleSwitchP4RuntimeAPI(device_id=id,grpc_port=grpc,
                                                                p4rt_path="main_p4rt.txt",
                                                                json_path="main.json")
            
            self.controllers[p4switch].reset_state()
            self.controllers_thrift[p4switch].reset_state()   
            self.setup_switch(p4switch)                             

        

class gar_py:
        def __init__(self, db_host = 'localhost', port = 8086, db = 'ddos_base', kern_type = 'linear', dbg = False):
                self.debug = dbg
                self.host = db_host
                self.port = port
                self.dbname = db
                self.client = influxdb.InfluxDBClient(self.host, self.port, 'telegraf', 'telegraf', self.dbname)
                #self.client = influxdb.InfluxDBClient(self.host, self.port, 'telegraf', 'telegraf', self.dbname)
                self.svm_inst = svm.SVC(kernel = kern_type)
                self.training_files = ["./DDoS_data_0.csv", "./DDoS_data_1.csv"]
                self.query = """select count(length) as num_of_packets,mean(length) as size_of_data from net group by time(3s,-3s) order by time desc limit 3"""
                self.train_svm()
                self.controller=myController()

        def train_svm(self):
                features, labels = [], []
 
                for fname in self.training_files:
                        meal = open(fname, "rt")
                        for line in meal:
                                if line.isspace():
                                        continue
                                data_list = line.rsplit(", ")
                                if 'None' in data_list:
                                        continue

                                for i in range(len(data_list)):
                                        if i < 2:
                                                data_list[i] = float(data_list[i])
                                        else:
                                                data_list[i] = int(data_list[i])

                                features.append(data_list[:2])
                                labels.append(data_list[2])
                        meal.close()
                print("features= {}".format(features))
                print("labels= {}".format(labels))
                self.svm_inst.fit(features, labels)

        def work_time(self):
                last_entry_time = "0"
                while True:
                        self.get_data(self.query).get_points()
                        entries = list(self.get_data(self.query).get_points(measurement = 'net'))
                        for new_entry in sorted(entries, key = lambda item: item['time']):
                        
                                print("Entry - {} - {} - {}".format(new_entry['time'],new_entry['num_of_packets'],new_entry['size_of_data']))
                                print("Old time - {}".format(last_entry_time))
                                if new_entry['time'] >= last_entry_time:
                                        last_entry_time = new_entry['time']
                                        if self.debug:
                                                print("\n** New entry **\n\tICMP info: " + str(new_entry['num_of_packets']) +" "+str(new_entry['size_of_data']))
                                        self.ring_the_alarm(self.under_attack(new_entry['num_of_packets'],new_entry['size_of_data']))
                        time.sleep(3)

        def under_attack(self, a, b):
                if b is None:
                  return False
                if self.debug:
                        print("\tCurrent prediction: " + str(self.svm_inst.predict([[a,b]])[0]))
                if self.svm_inst.predict([[a,b]])[0] == 1: 
                        return True
                else:
                        return False

        def get_data(self, petition):
                return self.client.query(petition)

        def ring_the_alarm(self, should_i_ring):
                if should_i_ring:
                        print("ring_the_alarm")
                        self.controller.switch_table_delete('s1')
                        self.controller.switch_table_delete('s3')

 

def ctrl_c_handler(s, f):
        print("\b\bShutting down MR. SVM... Bye!")
        exit(0)

       

if __name__ == "__main__":
        signal.signal(signal.SIGINT, ctrl_c_handler)
        ai_bot = gar_py(db_host = '127.0.0.1', dbg = True)
        ai_bot.work_time()