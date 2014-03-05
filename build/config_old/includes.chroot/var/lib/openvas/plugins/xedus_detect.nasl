# OpenVAS Vulnerability Test
# $Id: xedus_detect.nasl 57 2013-11-11 18:12:18Z jan $
# Description: Xedus detection
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
tag_summary = "The remote host runs Xedus Peer to Peer webserver, it provides
the ability to share files, music, and any other media, as well 
as create robust and dynamic web sites, which can feature 
database access, file system access, with full .net support.";

# Ref: James Bercegay of the GulfTech Security Research Team

if(description)
{
  script_id(14644);
  script_version("$Revision: 57 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-11 19:12:18 +0100 (Mo, 11. Nov 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
#  script_bugtraq_id(11071);
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_name("Xedus detection");

 
 desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Checks for presence of Xedus");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");

  script_family("Peer-To-Peer File Sharing");
  script_require_ports("Services/www", 4274);
  script_dependencies("httpver.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

exit(0); # FP-prone
port = 4274;
if(!get_port_state(port))exit(0);

 soc = http_open_socket(port);
 if(soc)
 {
  buf = http_get(item:"/testgetrequest.x?param='free%20openvas'", port:port);
  send(socket:soc, data:buf);
  rep = http_recv(socket:soc);
  if(egrep(pattern:"free openvas", string:rep))
  {
    set_kb_item(name:string("xedus/",port,"/running"),value: TRUE);
    set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
    security_note(port);
  }
  http_close_socket(soc);
 }
exit(0);
