# OpenVAS Vulnerability Test
# $Id: ciscoworks_detect.nasl 57 2013-11-11 18:12:18Z jan $
# Description: CiscoWorks Management Console Detection
#
# Authors:
# Tenable Network Security
#
# Copyright:
# Copyright (C) 2005 TNS
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
tag_summary = "The remote host appears to be running CiscoWorks, a LAN Management Solution,
on this port";

if(description)
{
 script_id(19559);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 57 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-11 19:12:18 +0100 (Mo, 11. Nov 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 
 name = "CiscoWorks Management Console Detection";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Checks for CiscoWorks";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2005 TNS");
 
 script_family("Service detection");
 script_dependencies("httpver.nasl");
 script_require_ports("Services/www", 1741);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");


port = get_kb_item("Services/www");
if ( ! port ) port = 1741;

if(get_port_state(port))
{
  req = http_get(item:"/login.html", port:port);
  soc  = open_sock_tcp(port);
  if ( ! soc ) exit(0);
  send(socket:soc, data:req);
  res = http_recv(socket:soc);

  if("<title>CiscoWorks</title>" >< res )
  {
    security_note(port);
    set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
  }
}
