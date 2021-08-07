from mininet.node import Switch
from mininet.moduledeps import pathCheck
from mininet.log import setLogLevel, info, error, debug
import os
import tempfile
from netstat import check_listening_on_port
from time import sleep

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

    
    def check_switch_started(self,pid):

        while True:
            if not os.path.exists(os.path.join("/proc",str(pid))):
                return False
            if check_listening_on_port(self.thrift_port):
                return True
            sleep(1)
    
    def start(self,controllers):
        info("Start of P4 switch {}.\n".format(self.name))
        args = [self.sw_path]
        for port, intf in self.intfs.items():
            if not intf.IP():
                args.extend(['-i',str(port)+"@"+intf.name])
            
        if self.pcap:
            args.append("--pcap {}".format(self.pcap))
        if self.thrift_port:
            args.extend(['--thrift-port', str(self.thrift_port)])
        if self.nanomsg:
            args.extend(['--nanolog',self.nanomsg])

        args.extend(['--device-id', str(self.device_id)])
        P4Switch.device_id+=1
        args.append(self.json_path)
        info(' '.join(args) + "\n")

        pid = None
        with tempfile.NamedTemporaryFile() as f:
            # self.cmd(' '.join(args) + ' > /dev/null 2>&1 &')
            self.cmd(' '.join(args) + ' >' + self.log_file + ' 2>&1 & echo $! >> ' + f.name)
            pid = int(f.read())
        debug("P4 switch {} PID is {}.\n".format(self.name,pid))
        if not self.check_switch_started(pid):
            error("P4 switch {} did not start correctly.\n".format(self.name))
            exit(1)
        info("P4 switch {} has been started.\n".format(self.name))
    
    def stop(self):
        self.output.flush()
        self.cmd("kill {}".format(self.sw_path))
        self.cmd('wait')
        self.deleteIntfs()

    def attach(self,intf):
        info("Connect data port")
        assert(0)
    def detach(self,intf):
        info("Disconnect data port")
        assert(0)
        