from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from p4utils.utils.helper import load_topo
import influxdb, datetime, time, os, signal
from influxdb_client.client.util import date_utils
from dateutil.tz import tzlocal
from sklearn import svm
blockip=[]

class myController(object):

    def __init__(self):
        self.topo = load_topo('topology.json')
        self.controllers = {}
        self.connect_to_switches()

    def connect_to_switches(self):
        device = 1
        grpc = 9559
        for p4switch in self.topo.get_p4switches():
            print("P4 switch - {}".format(p4switch))
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port)
            #self.controllers[p4switch] = SimpleSwitchP4RuntimeAPI(device_id=device,grpc_port=grpc,
            #                                                    p4rt_path="main_p4rt.txt",
            #                                                    json_path="main.json")  

class gar_py:
        def __init__(self, db_host = 'localhost', port = 8086, db = 'ddos_base', kern_type = 'linear', dbg = False):
                self.debug = dbg
                self.host = db_host
                self.port = port
                self.dbname = db
                self.client = influxdb.InfluxDBClient(self.host, self.port, 'telegraf', 'telegraf', self.dbname)
                self.svm_inst = svm.SVC(kernel = kern_type)
                self.training_files = ["./DDoS_data_0.csv", "./DDoS_data_1.csv"]
                self.query = "select count(length) as a,mean(length) as b from net group by time(3s) order by time desc limit 3"
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
                date_utils.date_helper = date_utils.DateHelper(timezone=tzlocal())
                last_entry_time = "0"
                while True:
                        for new_entry in list(self.get_data(self.query).get_points(measurement = 'net')):
                                if new_entry['time'] > last_entry_time:
                                        last_entry_time = new_entry['time']
                                        if self.debug:
                                                print("\n** New entry **\n\tICMP info: " + str(new_entry['a']) +" "+str(new_entry['b']))
                                        self.ring_the_alarm(self.under_attack(new_entry['a'],new_entry['b']))
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
                        #if "10.0.0.1" not in blockip:
                           #      self.controller.controllers["s1"].table_add("block_pkt", "drop", [str("10.0.0.1")], [])
                           #      blockip.append("10.0.0.1")

 

def ctrl_c_handler(s, f):
        print("\b\bShutting down MR. SVM... Bye!")
        exit(0)

       

if __name__ == "__main__":
        signal.signal(signal.SIGINT, ctrl_c_handler)
        ai_bot = gar_py(db_host = '127.0.0.1', dbg = True)
        ai_bot.work_time()