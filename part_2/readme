Advanced Topology

1. Pass Mininet the custom file (adv_topo.py) and run the custom topology
    $ sudo mn -c
    $ sudo mn --custom adv_topo.py --topo advtopo --mac --controller remote

2. Put the router.py file into this folder: ./pox/pox/misc
   *The fake gateway IP list is changed to fit this topology.

3. Run the router with full payload under the path ./pox
    $./pox.py log.level --DEBUG misc.router misc.full_payload

4. Test with pingall, iperf command in Mininet.


Create Firewall

1. Put the firewall.py file into this folder: ./pox/pox/misc , and run the
router with full payload under the path ./pox
    $./pox.py log.level --DEBUG misc.firewall misc.full_payload

2. Run and test. The firewall rules is hardcoded in firewall.py
Allowable parameters includes: dpid, port, dl_src, dl_dst, dl_type, nw_proto, nw_src,
nw_dst, tp_src, and tp_dst. Set to None if want wildcards. Note the first term is
the dpid of a certain switch, where 0 stands for all switches.

e.g.: firewall = [[0,None,None,None,0x0800,6,None,None,6000,None],]
    This rule matches any TCP packet whose send port is 6000 and drop it.
dl_type = 0X0800 represents IPv4 and nw_proto = 6 represents TCP, which are the
necessary prerequisites for tp_src and tp_dst match.
