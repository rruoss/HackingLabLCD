# OpenVAS Vulnerability Test
# $Id: cfengine_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: cfengine detection and local identification
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
tag_summary = "The cfengine service is running on this port.  

Cfengine is a language-based system for testing and configuring
Unix and Windows systems attached to a TCP/IP network.";

if(description)
{
 script_id(14315);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "cfengine detection and local identification";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "check for the presence of cfengine with local identification version checks if possible";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "General";
 script_family(family);
 script_require_ports(5308);

 script_dependencies("gather-package-list.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


port = 5308;

if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);


ver = get_kb_item("cfengine/version");
if ( ! ver ) exit(0);


set_kb_item(name:"cfengine/running", value:TRUE);

report = "
cfengine version "+ver+" is running on this port.
cfengine is a language-based system for testing and configuring 
unix and windows systems attached to a TCP/IP network.";

security_note(port:port, data:report);
