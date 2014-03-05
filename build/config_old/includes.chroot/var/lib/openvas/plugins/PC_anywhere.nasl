# OpenVAS Vulnerability Test
# $Id: PC_anywhere.nasl 17 2013-10-27 14:01:43Z jan $
# Description: pcAnywhere
#
# Authors:
# Mathieu Perrin <mathieu@tpfh.org>
# modded by John Jackson <jjackson@attrition.org> to pull hostname
# changes by rd : more verbose report on hostname
# changes by Tenable Network Security: new detection code
#
# Copyright:
# Copyright (C) 1999 Mathieu Perrin
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
tag_summary = "pcAnywhere is running on this port.";

tag_solution = "Disable this service if you do not use it.";

if(description)
{
 script_id(10006);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "pcAnywhere";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for the presence pcAnywhere";
 script_summary(summary);


 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 1999 Mathieu Perrin");

 family = "Windows";
 script_family(family);
 script_dependencies("find_service.nasl");


 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
exit(0);
}


#
# The script code starts here
#

port = 5632;
if (!get_port_state(port))
  exit (0);

soc = open_sock_udp(port);
if (!soc) exit(0);

send (socket:soc, data:"ST");
buf = recv(socket:soc, length:2);
if ("ST" >< buf)
  security_note (port);
