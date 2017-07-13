Customer topology

1. Pass Mininet the custom file (adv_topo.py) and run the custom topology
    $ sudo mn -c
    $ sudo mn --custom adv_topo.py --topo advtopo --mac --controller remote

   This topology has 3 switches, each switch connect to 2 hosts. The topology
   looks like this:

      h3      h5     h7
        \     |     /
         s1 - s2 - s3
        /     |     \
      h4      h6     h8

2. Put the router.py file into this folder: ./pox/pox/misc
   *The fake gateway IP list is changed to fit this topology.

3. Run the router with full payload under the path ./pox
    $./pox.py log.level --DEBUG misc.router misc.full_payload

4. Test with pingall, iperf command in Mininet.
