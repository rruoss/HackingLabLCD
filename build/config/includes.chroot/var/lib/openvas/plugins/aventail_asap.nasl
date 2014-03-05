# OpenVAS Vulnerability Test
# $Id: aventail_asap.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Aventail ASAP detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
tag_summary = "The remote host seems to be an Aventail SSL VPN appliance, 
connections are allowed to the web console management.

Letting attackers know that you are using this software will help 
them to focus their attack or will make them change their strategy.
In addition to this, an attacker may attempt to set up a brute force attack
to log into the remote interface.";

tag_solution = "Filter incoming traffic to this port";

if(description)
{
 script_id(17583);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 
 name = "Aventail ASAP detection";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Aventail ASAP Management Console management";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 
 family = "Service detection";
 script_family(family);
 script_dependencies("http_version.nasl");

 script_require_ports(8443);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

function https_get(port, request)
{
    if(get_port_state(port))
    {

         soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);
         if(soc)
         {
            send(socket:soc, data:string(request,"\r\n"));
            result = http_recv(socket:soc);
            close(soc);
            return(result);
         }
    }
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = 8443;
if(get_port_state(port))
{
 req = http_get(item:"/console/login.do", port:port);
 rep = https_get(request:req, port:port);
 if( rep == NULL ) exit(0);
 #<title>ASAP Management Console Login</title>
 if ("<title>ASAP Management Console Login</title>" >< rep)
 {
   security_note(port);
 }
}