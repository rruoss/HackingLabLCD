# OpenVAS Vulnerability Test
# $Id: vnc.nasl 41 2013-11-04 19:00:12Z jan $
# Description: Check for VNC
#
# Authors:
# Patrick Naubert
# Modified by Georges Dagousset <georges.dagousset@alert4web.com> :
#	- warning with the version
#	- detection of other version
#	- default port for single test
#
# Copyright:
# Copyright (C) 2000 Patrick Naubert
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
tag_summary = "The remote host is running a remote display software (VNC)

Description :

The remote server is running VNC, a software which permits a 
console to be displayed remotely.

This allows authenticated users of the remote host to take its 
control remotely.";

tag_solution = "Make sure the use of this software is done in accordance with your
corporate security policy, filter incoming traffic to this port.";

# This is version 2.0 of this script.

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(10342);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "Check for VNC";
 script_name(name);

 script_description(desc);
 
 summary = "Checks for VNC";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2000 Patrick Naubert");
 script_family( "Service detection");
 script_dependencies("find_service1.nasl");
 script_require_ports("Services/vnc", 5900, 5901, 5902);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

function probe(port)
{
 # if (! get_port_state(port)) return 0;
 r = get_kb_item("FindService/tcp/" + port + "/spontaneous");
 if ( ! r ) return 0;
 version = egrep(pattern:"^RFB 00[0-9]\.00[0-9]",string:r);
 if(version)
   {
      report = desc + '\n\nPlugin output :\nThe version of the VNC protocol is : ' + version;
      security_note(port:port, data:report);
   }
}

port = get_kb_item("Services/vnc");
if(port)probe(port:port);
else
{
 for (port=5900; port <= 5902; port = port+1) {
  probe(port:port);
 }
}
