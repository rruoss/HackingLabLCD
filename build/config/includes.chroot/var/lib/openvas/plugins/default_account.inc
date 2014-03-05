# OpenVAS Vulnerability Test
# $Id$
# Description: Support for various ways of determining if an account is valid
#
# Authors:
# Renaud Deraison
#
# Copyright:
# Copyright (C) 2004 Renaud Deraison
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

include("ssh_func.inc");

#
# Private functions
# 

function recv_until(socket, pattern)
{
 local_var r, i, buf;
 i = 0;
 while ( TRUE )
 {
  i ++;
  if ( i > 65535 ) return NULL;
  r = recv(socket:socket, length:1);
  if ( strlen(r) == 0 ) return NULL;
  buf += r;
  if ( egrep(pattern:pattern,string:buf) ) return buf;
 }
}


function _check_telnet(port, login, password)
{
 local_var soc, res;
 soc = open_sock_tcp(port);
 if(!soc)return(0);

 res = telnet_init(soc);
 res += recv_until(socket:soc, pattern:"ogin:");
 if ( ! res ) exit(0);

 send(socket:soc, data:login + '\r\n');
 if ( isnull(password) )
  {
   send(socket:soc, data:'id\r\n');
   res = recv_until(socket:soc, pattern:"uid=");
   close(soc);
   if ( res ) return 1; 
   else return 0;
  }


 res = recv_until(socket:soc, pattern:"word:");
 if ( res == NULL ) 
 {
  close(soc);
  return 0;
 }

 send(socket:soc, data:password + '\r\n');
 send(socket:soc, data:'id\r\n');
 
 res = recv_until(socket:soc, pattern:"uid=");
 close(soc);
 if ( res ) return 1;
 else return 0;

}

#-------------------------------------------------------------------#


function check_account(login, password)
{
 local_var port, ret;
 
  # Prefer login thru SSH rather than telnet
  port = get_kb_item("Services/ssh");
  if ( ! port ) port = 22; 
  soc = open_sock_tcp(port);
  if ( soc )
  {
  ret = ssh_login(socket:soc, login:login, password:password);
  close(soc);
  if ( ret == 0 ) return port;
  #else return 0; 
  }

 port = get_kb_item("Services/telnet");
 if(!port) port = 23;
 
 if(get_port_state(port))
 {
  if ( isnull(password) ) password = "";
  res = _check_telnet(port:port, login:login, password:password);
  if(res)
   return(port);
 }
 return(0);
}