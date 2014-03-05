# OpenVAS Vulnerability Test
# $Id: cp-firewall-webauth.nasl 17 2013-10-27 14:01:43Z jan $
# Description: CheckPoint Firewall-1 Web Authentication Detection
#
# Authors:
# Yoav Goldberg <yoavg@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 SecuriTeam
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
tag_solution = "if you do not use this service, disable it";

tag_summary = "A Firewall-1 web server is running on this port and serves web
authentication requests.

This service allows remote attackers to gather usernames and passwords 
through a brute force attack.

Older versions of the Firewall-1 product allowed verifying usernames 
prior to checking their passwords, allowing attackers to easily
bruteforce a valid list of usernames.";

if(description)
{
 script_id(10676);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
script_name("CheckPoint Firewall-1 Web Authentication Detection");
  desc = "
  Summary:
  " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 script_summary("The remote CheckPoint Firewall-1 can be authenticated with via a web interface");
 script_category(ACT_GATHER_INFO);
 script_family("Firewalls");
 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 script_dependencies("find_service.nasl", "httpver.nasl");
 script_require_ports("Services/www", 900);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# Actual script starts here
#
include("http_func.inc");
include("misc_func.inc");

quote = raw_string(0x22);

strcheck1 = string("Authentication Form");
strcheck2 = string("Client Authentication Remote");
strcheck3 = string("FireWall-1 message");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:900);


foreach port (ports)
{
 soc = http_open_socket(port);
 if(soc)
 {
  buf = http_get(item:"/", port:port);
  send(socket:soc, data:buf);
  re = http_recv(socket:soc);
  http_close_socket(soc);
  if((strcheck3 >< re) && (strcheck2 >< re) && (strcheck1 >< re))
	{
	security_warning(port);
	}
 }
}
