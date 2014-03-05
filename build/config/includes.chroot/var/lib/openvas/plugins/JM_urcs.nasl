# OpenVAS Vulnerability Test
# $Id: JM_urcs.nasl 17 2013-10-27 14:01:43Z jan $
# Description: URCS Server Detection
#
# Authors:
# J.Mlødzianøwski <jøseph[at]rapter.net>
#
# Copyright:
# Copyright (C) 9/2004 J.Mlodzianowski
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
tag_summary = "This host appears to be running URCS Server. Unmanarc Remote Control Server 
can be used/installed silent as a 'backdoor' which may allow an intruder to 
gain remote access to files on the remote system. If this program was not 
installed for remote management then it means the remote host has been
compromised. 

An attacker may use it to steal files, passwords, or redirect ports on the
remote system to launch other attacks.";

tag_solution = "see http://www.rapter.net/jm5.ht";


if(description)
{
 script_id(15405);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 name = "URCS Server Detection";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Determines the presence of the URCS Server";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright("This script is Copyright(C) 9/2004 J.Mlodzianowski");
 family = "Malware";
 script_family(family);
 script_dependencies("find_service2.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://urcs.unmanarc.com");
 script_xref(name : "URL" , value : "http://securityresponse.symantec.com/avcenter/venc/data/backdoor.urcs.html");
 exit(0);
}

#
# The code starts here:
#

include("misc_func.inc");
include('global_settings.inc');

if ( ! thorough_tests  )
{
 port = 3360;
}
else
{
 port = get_kb_item("Services/unknown");
 if ( ! service_is_unknown(port:port) ) exit(0);
 if ( ! port ) port = 3360;
}
# Default port for URCS Server is 3360
# Default port for URCS Client is 1980
 if (get_port_state(port))
{
 soc= open_sock_tcp(port);
 if(soc)
{
 send(socket:soc, data:'iux');
 r = recv(socket:soc, length:817);
 if ( "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" >< r ) 
	security_hole(port);
 close(soc);
 }
} 
