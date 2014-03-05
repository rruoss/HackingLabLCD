# OpenVAS Vulnerability Test
# $Id: nntp_func.inc 10917 2011-05-12 19:59:39Z jan $
# Description: Functions for nntp
#
# Authors:
# Michel Arboi
#
# Copyright:
# Copyright (C) 2002-2005 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

# NNTP protocol is defined by RFC 977
# NNTP message format is defined by RFC 1036 (obsoletes 850); see also RFC 822.

function nntp_auth(socket, username, password)
{
 local_var	 buff;
 if (!username) return (0);

 send(socket:socket, data: string("AUTHINFO USER ", username, "\r\n"));
 buff = recv_line(socket:socket, length:2048);
 send(socket:socket, data: string("AUTHINFO PASS ", password, "\r\n"));
 buff = recv_line(socket:socket, length:2048);
 if ("502 " >< buff) { 
  debug_print(string("Bad username/password for NNTP server"));
  return (0);
 }
 return (1);
}

function nntp_connect(port, username, password)
{
  local_var s, a;
  s = open_sock_tcp(port);
  if (s) { 
   buff = recv_line(socket: s, length: 2048);
   a = nntp_auth(socket: s, username: username, password: password); 
   if (! a) { close(s); return; }
  }
  return (s);
}

function nntp_post(socket, message)
{
  local_var	buff;

  if (! socket) { return (0); }
  send(socket: socket, data:string("POST\r\n"));
  buff = recv_line(socket:s, length: 2048);

  # 340 = Go ahead; 440 = posting prohibited
  if ("340 " >< buff) {
    send(socket: socket, data: message);
    buff = recv_line(socket: socket, length: 2048);
    if ("240 " >< buff) { return (1); }
    if (ereg(pattern: "^4[34][0-9] +.*unwanted distribution .*local", 
             string: buff, icase:1) &&
        ereg(pattern: "Distribution: +local", string: message)) {
	return -1;
    }
  }
 return (0);
}

function nntp_article(id, timeout, port, username, password)
{
  local_var	t;
  for (t=0; t < timeout; t=t+5)
  {
    sleep(5);
    s = nntp_connect(port:port, username: username, password: password);
    if (s) {
      send(socket:s, data: string("ARTICLE ", id, "\r\n"));
      buff = recv_line(socket: s, length: 2048);
      send(socket:s, data: string("QUIT\r\n"));
      close(s);
      # display(string("Article > ", buff));
      # WARNING! If the header X-OpenVAS is removed, change this line!
      if (ereg(pattern:"^220 .*X-OpenVAS:", string: buff)) { return (buff); }
    }
  }
  return (0);
}

function nntp_make_id(str)
{
 local_var	id;
 # RFC 822 says that should use a full domain name. Some new servers 
 # check that the domain part is valid so we use "openvas.org"
 # We do not check "str", but it should not contain '@' or '>'
 id=string("<", str, ".x", rand(), "@openvas.org>");
 return(id);
}
