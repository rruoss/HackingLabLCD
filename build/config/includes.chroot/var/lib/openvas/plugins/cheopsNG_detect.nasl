# OpenVAS Vulnerability Test
# $Id: cheopsNG_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Cheops NG Agent Detection
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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

include("revisions-lib.inc");
tag_summary = "The remote host is running a network management tool. 

Description :

The remote host is running a Cheops NG agent.  Cheops NG is an
open-source network management tool, and the cheops-agent provides a
way for remote hosts to communicate with the tool and use it to map
your network, port scan machines and identify running services.";

if(description)
{
 script_id(20160);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name( "Cheops NG Agent Detection");
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 script_summary( "Cheops NG agent is running");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 script_family( "Service detection");
 script_dependencies("find_service.nasl", "find_service2.nasl");
 script_require_ports(2300, "Services/unknown");
 script_xref(name : "URL" , value : "http://cheops-ng.sourceforge.net/");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");
include("global_settings.inc");

m1 = '\x00\x00\x00\x14\x00\x0c\x00\x04\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00';
m2 = '\x00\x00\x00\x20\x00\x0c\x00\x02\x00\x00\x00\x00\x01\x00\x00\x7f\x01\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\xb8\xdf\x0d\x08';

if (thorough_tests)
 ports = get_kb_list("Services/unknown");
else
 ports = NULL;
ports = add_port_in_list(list: ports, port: 2300);

prev = 0;
foreach port (ports)
{
 if (port && port != prev && get_port_state(port) && 
     service_is_unknown(port:port))
 {
  prev = port;
  soc = open_sock_tcp(port);
  if (soc)
  {
   send(socket: soc, data: m1);
   r = recv(socket: soc, length: 512);
   if (strlen(r) > 0)
   {
    debug_print('Service on port ', port, ' answers to first request - L=', strlen(r), '\n');
    if (substr(r, 0, 7) == '\x00\x00\x00\x10\x00\x0c\x00\x6c')
    {
     security_note(port: port);
     register_service(port: port, proto: 'cheops-ng');
     set_kb_item(name: 'cheopsNG/password', value: port);
    }
    close(soc);
    continue;
   }
   send(socket: soc, data: m2);
   r = recv(socket: soc, length: 512);
   l = strlen(r);
   debug_print('reply length = ', l, '\n');
   if (l >= 8 && substr(r, 0, 2) == '\0\0\0' && '\x01\x00\x00\x7f' >< r)
   {
    security_note(port);
    register_service(port: port, proto: 'cheops-ng');
     set_kb_item(name: 'cheopsNG/unprotected', value: port);
   }
   close(soc);
  }
 }
}
