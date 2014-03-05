# OpenVAS Vulnerability Test
# $Id$
# Description: Methods for handling POP3
#
# Authors:
# Anonymous
#
# Copyright:
# Copyright (C) 2004 Anonymous
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
# -*- Fundamental -*-


function get_pop3_banner (port)
{
  local_var sb, banner, soc;
  
  sb = string("pop3/banner/", port);
  banner = get_kb_item(sb);
  if(banner) return (banner);
  if ( get_kb_item("pop3/" + port + "/broken") ) 
	return NULL;

  if(! get_port_state(port)) return (0);
  soc = open_sock_tcp(port);
  if (! soc) {
	set_kb_item(name:"pop3/" + port + "/broken", value:TRUE);
	return NULL;
	}
  banner =  recv_line(socket: soc, length:4096);
  close(soc);
  if(! banner ) {
	set_kb_item(name:"pop3/" + port + "/broken", value:TRUE);
	return NULL;
	}
	
  
  replace_kb_item(name: sb, value: banner);
  return(banner);
}

