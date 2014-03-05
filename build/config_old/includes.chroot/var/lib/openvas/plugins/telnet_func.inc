# OpenVAS Vulnerability Test
# $Id$
# Description: Methods to handle telnet
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi <arboi@alussinan.org>
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

# $Revision: 1.8 $

OPT_WILL 	= 0xfb;
OPT_WONT 	= 0xfc;
OPT_DO   	= 0xfd;
OPT_DONT 	= 0xfe;

OPT_SUBOPT 	= 0xfa;
OPT_ENDSUBOPT 	= 0xf0;

function get_telnet_banner(port)
{
  local_var sb, banner, soc;
  sb = string("telnet/banner/", port);
  banner = get_kb_item(sb);
  if (banner) return(banner);

  soc = open_sock_tcp(port);
  if(!soc) return (0);
  banner = telnet_negotiate(socket:soc);
  close(soc);
  if(strlen(banner))
    replace_kb_item(name: sb, value: str_replace(find:raw_string(0), replace:'', string:banner));
  return(banner);
}


function telnet_negotiate(socket)
{
 local_var opt, code, s, counter, counter2, buf, prev;

 counter = 0;

 while ( TRUE )
 {
  s   = recv(socket:socket, length:1, timeout:3);
  if ( !strlen(s) ) break;
  if ( ord(s[0]) != 0xff) buf += s;
  else {
   counter ++;
   s  = recv(socket:socket, length:2);

   if ( ord(s[0]) == OPT_DO ) send(socket:socket,data:raw_string(0xff, OPT_WONT) + s[1]);
   if ( ord(s[0]) == OPT_WILL ) send(socket:socket,data:raw_string(0xff, OPT_DONT) + s[1]);
   if ( ord(s[0]) == OPT_SUBOPT )
	{
	 # The remote telnet server is autistic :/
	 prev = recv(socket:socket, length:1);
         counter2 = 0;
	 while ( ord(prev) != 0xff && ord(s[0]) != OPT_ENDSUBOPT )
	   {
	    prev = s;
 	    # No timeout - the answer is supposed to be cached
	    s    = recv(socket:socket, length:1, timeout:0);
	    if ( ! strlen(s) ) return buf;
	    counter2++;
	    if ( counter2 >= 100 ) return buf;
	   }
	}
  
   # Not necessary and may introduce endless loops
   #if ( ord(s[0]) == OPT_DONT ) send(socket:socket,data:raw_string(0xff, OPT_WONT) + s[1]);
   #if ( ord(s[0]) == OPT_WONT ) send(socket:socket,data:raw_string(0xff, OPT_DONT) + s[1]);
  }
  if ( counter >= 100 || strlen(buf) >= 4096 ) break;
 }

 
 return buf;
}

function set_telnet_banner(port, banner)
{
  local_var sb;
  sb = string("telnet/banner/", port);
  replace_kb_item(name: sb, value: str_replace(find:raw_string(0), replace:'', string:banner));
}
