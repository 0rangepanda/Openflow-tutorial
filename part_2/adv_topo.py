from mininet.topo import Topo

class AdvTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        switch1 = self.addSwitch( 's1' )
        switch2 = self.addSwitch( 's2' )

        host3 = self.addHost( 'h3', ip="10.0.1.2/24", defaultRoute = "via 10.0.1.1" )
        host4 = self.addHost( 'h4', ip="10.0.1.3/24", defaultRoute = "via 10.0.1.1" )
        host5 = self.addHost( 'h5', ip="10.0.2.2/24", defaultRoute = "via 10.0.2.1" )

        # Add links
        self.addLink( switch1, switch2 )
    
        self.addLink( switch1, host3 )
        self.addLink( switch1, host4 )
        self.addLink( switch2, host5 )



topos = { 'advtopo': ( lambda: AdvTopo() ) }
