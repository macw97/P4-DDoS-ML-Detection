from mininet.node import Host

class P4Host(Host):
    def config(self,**_params):
        r = super(Host,self).config(**_params)
        self.defaultIntf().rename("eth0")

        for off in ["rx","tx","sg"]:
            command = "/sbin/ethtool --offload eth0 {} off"
            self.cmd(command.format(off))

        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

        return r

    def information(self):
        print("************\n{}\ndefault interface:\n\t{}\n\t{}\n\t{}\n************".format(
            self.name,
            self.defaultIntf().name,
            self.defaultIntf().IP(),
            self.defaultIntf().MAC()
        ))
