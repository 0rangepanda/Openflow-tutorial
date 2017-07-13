Creating a learning switch

1. Create a simple 3-host topology in Mininet
    $ sudo mn -c
    $ sudo mn --topo single,3 --mac --switch ovsk --controller remote

2. Put the learning_switch.py file into this folder: ./pox/pox/misc

3. Run the learning switch under ./pox
    $./pox.py log.level --DEBUG misc.learning_switch

4. Test with pingall, iperf command in Mininet

5. switch_resend.py is the version without installing flow mod. The throughput
of this controller is much lower than the result of learning_switch.py

6. switch_multi.py is the version for multi switch topology. Test this with the
following topology command in Mininet:
    $ sudo mn --topo linear --switch ovsk --controller remote


Router exercise

1. Pass Mininet the custom file (mytopo.py) and run the custom topology
    $ sudo mn -c
    $ sudo mn --custom mytopo.py --topo mytopo --mac --controller remote

2. Put the router.py file into this folder: ./pox/pox/misc

3. Run the router with full payload under ./pox
    $./pox.py log.level --DEBUG misc.router misc.full_payload

4. Test with pingall, iperf command in Mininet. Also, ping an IP that does not
exist will get ICMP unreachable message.

5. router_resend.py is the version without installing flow mod. The throughput
of this controller is much lower than the result of router.py
