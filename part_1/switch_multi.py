from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}


  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)



  def act_like_switch (self, packet, packet_in, dpid):
    """
    Implement switch-like behavior.
    """

    if dpid not in self.mac_to_port:
      log.debug("Add switch %s", str(dpid))
      self.mac_to_port[dpid] = {}

    self.mac_to_port[dpid][packet.src] = packet_in.in_port


    #if the port associated with the destination MAC of the packet is known:
    if packet.dst in self.mac_to_port[dpid]:
      # Send packet out the associated port
      self.resend_packet(packet_in, self.mac_to_port[dpid][packet.dst])

      log.debug("Switch " + str(dpid) + " installing flow. src:"+str(packet.src)
      +" dst:"+str(packet.dst)+" Inport:"+str(packet_in.in_port))

      msg = of.ofp_flow_mod()
      #
      ## Set fields to match received packet
      #msg.match.in_port = packet_in.in_port
      #msg.match.dl_src = packet.src
      msg.match.dl_dst = packet.dst
      #
      #< Set other fields of flow_mod (timeouts? buffer_id?) >
      msg.idle_timeout = 1000
      #msg.idle_timeout = 3 #rules expire after idle for 3 sec
      #< Add an output action, and send -- similar to resend_packet() >
      out_action = of.ofp_action_output(port = self.mac_to_port[dpid][packet.dst])
      msg.actions.append(out_action)
      self.connection.send(msg)

    else:
      # Flood the packet out everything but the input port
      # This part looks familiar, right?
      self.resend_packet(packet_in, of.OFPP_ALL)


  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    dpid = event.connection.dpid

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    #self.act_like_hub(packet, packet_in)
    self.act_like_switch(packet, packet_in, dpid)



def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
