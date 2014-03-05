# OpenVAS Vulnerability Test
# $Id: DDI_Netware_Management_Portal.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Unprotected Netware Management Portal
#
# Authors:
# H D Moore <hdmoore@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2001 Digital Defense Inc.
# Copyright (C) 2001 H D Moore <hdmoore@digitaldefense.net>
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
tag_summary = "The Netware Management Portal software is running on this machine. The 
Portal allows anyone to view the current server configuration and 
locate other Portal servers on the network. It is possible to browse the 
server's filesystem by requesting the volume in the URL. However, a valid 
user account is needed to do so.";

tag_solution = "Disable this service if it is not in use or block connections to
this server on TCP ports 8008 and 8009.";

if(description)
{
 script_id(10826);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Unprotected Netware Management Portal";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);

 summary = "Unprotected Netware Management Portal";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 Digital Defense Inc.");
 family = "General";
 script_family(family);

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 8008);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


# ssl version sometimes on port 8009
port = get_http_port(default:8008);
if( ! port ) exit(0);
if(get_port_state(port))
{
    res = http_get_cache(item:"/", port:port);
    if (res && "NetWare Server" >< res )
     security_warning(port);
}
