# OpenVAS Vulnerability Test
# $Id: oracle_web_admin_server.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Oracle Web Administration Server Detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com>
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
tag_summary = "We detected the remote web server as an Oracle 
Administration web server. This web server enables attackers to configure 
your Oracle Database server if they gain access to a valid authentication 
username and password.";

tag_solution = "Disable the Oracle Administration web server if it is unnecessary,
or block the web server's port number on your Firewall.";

if(description)
{
 script_id(10738);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"1.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Low");
 name = "Oracle Web Administration Server Detection";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);

 summary = "Oracle Web Administration Server Detect";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "General";
 script_family(family);

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 8888);
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
include("misc_func.inc");
 
ports = add_port_in_list(list:get_kb_list("Services/www"), port:8888);
 
foreach port (ports)
{
  buf = http_get_cache(item:"/", port:port);
  if (("401 Unauthorized" >< buf) && ("Oracle_Web_Listener" >< buf) && ("WWW-Authenticate: Basic Realm=" >< buf))
   security_note(port:port);
}

