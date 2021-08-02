from mininet.node import Switch
from mininet.moduledeps import pathCheck
from mininet.log import setLogLevel, info, error, debug
import os
from netstat import check_listening_on_port

class P4Switch(Switch):
    device_id = 0

    def __init__(self,name,sw_path = None,
                 json_path = None,
                 thrift_port = None,
                 pcap = False,
                 log_file = None,
                 device_id = None,
                 **kwargs):

        super(P4Switch,self).__init__(self,name,**kwargs)
        assert(sw_path is None ),"sw_path is null"
        assert(json_path is None),"json_path is null"
        pathCheck(sw_path)

        if not os.path.isfile(json_path):
            error("Invalid json_path.\n")
            exit(1)
        
        self.sw_path = sw_path
        self.json_path = json_path
        
        self.thrift_port = thrift_port
        if check_listening_on_port(self.thrift_port):
            error("{} cannot bind port {} because it is bound by another process\n".format(self.name,self.grpc_port))
            exit(1)
        self.pcap = pcap
        if log_file is None:
            self.log_file = "/tmp/p4s.{}.log".format(self.name)
        else:
            self.log_file = log_file
        
        if device_id is None:
            self.device_id = P4Switch.device_id
            P4Switch.device_id += 1
        else:
            self.device_id = device_id
            P4Switch.device_id = max(P4Switch.device_id,device_id)
        
        self.nanomsg = "ipc:///tmp/bm-{}-log.ipc".format(self.device_id)