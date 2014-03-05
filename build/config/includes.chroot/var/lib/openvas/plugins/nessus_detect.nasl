# OpenVAS Vulnerability Test
# $Id: nessus_detect.nasl 41 2013-11-04 19:00:12Z jan $
# Description: A Nessus Daemon is running
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Modified by Georges Dagousset <georges.dagousset@alert4web.com> :
#   - port 1241 (IANA) added
#   - rcv test is more strict
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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
tag_summary = "The port TCP:3001 or TCP:1241 is open, and since this is the default port
for the Nessus daemon, this usually indicates a Nessus daemon is running,
and open for the outside world.
An attacker can use the Nessus Daemon to scan other site, or to further
compromise the internal network on which nessusd is installed on.
(Of course the attacker must obtain a valid username and password first, or
a valid private/public key)";

tag_solution = "Block those ports from outside communication, or change the
default port nessus is listening on.";

if(description)
{
 script_id(10147);
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "A Nessus Daemon is running";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "A Nessus Daemon is running";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 1999 SecuriTeam");
 script_family("Service detection");
 script_require_ports(1241);
 script_dependencies("find_service2.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");
  
function probe(port)
{
  supported = "";
  p[0] = "< NTP/1.2 >";
  #p[1] = "< NTP/1.0 >";


  #
  # We don't want to be fooled by echo & the likes
  #
  soc = open_sock_tcp(port);
  if(soc)
  {
    send(socket:soc, data:string("TestThis\r\n"));
    r = recv_line(socket:soc, length:10);
    if("TestThis" >< r)return(0);
    close(soc);
  }
  
  

  for(count=0; p[count] ; count=count+1)
  {
   soc = open_sock_tcp(port);
   if (soc)
   {
    senddata = string(p[count],"\n");
    send(socket:soc, data:senddata);
    recvdata = recv_line(socket:soc, length:20);
    if (ereg(pattern:string("^", p[count]), string:recvdata))
		supported = string(supported,p[count]);
    else 	
    		count = max + 1;
    close(soc);
   }
   else count = max + 1;
  }
  if (strlen(supported) > 0)
  {
    security_warning(port:port, data:string("A Nessus Daemon is listening on this port."));
    register_service(port: port, proto: "nessus");
  }
}


port = get_kb_item("Services/unknown");
if(port)
{
 if (known_service(port: port)) exit(0); 
 if(get_port_state(port))
  probe(port:port);
}
else
{
 if(get_port_state(1241))
  probe(port:1241);
}
