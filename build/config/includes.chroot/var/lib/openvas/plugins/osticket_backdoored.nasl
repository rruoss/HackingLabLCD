# OpenVAS Vulnerability Test
# $Id: osticket_backdoored.nasl 17 2013-10-27 14:01:43Z jan $
# Description: osTicket Backdoored
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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
tag_summary = "There is a vulnerability in the current version of osTicket
that allows an attacker to upload an PHP script, and then access it
causing it to execute.
This attack is being actively exploited by attackers to take over
servers. This script tries to detect infected servers.";

tag_solution = "1) Remove any PHP files from the /attachments/ directory.
2) Place an index.html file there to prevent directory listing of that
directory.
3) Upgrade osTicket to the latest version.";

# From: Guy Pearce <dt_student@hotmail.com>
# Date: 21.6.2004 08:01
# Subject: Multiple osTicket exploits!

# This script detects those osTicket systems that were backdoored,
# not the vulnerability

if(description)
{
  script_id(12649);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  name = "osTicket Backdoored";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);
 
  summary = "Detect osTicker Backdoored";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");

  family = "General";
  script_family(family);
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if ( ! can_host_php(port:port) ) exit(0);

if ( ! get_kb_item("www/" + port + "/osticket" )  ) exit(0);

function check_dir(path)
{
 req = http_get(item:path +  "/attachments/", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) return(0);
 if ("[DIR]" >< res)
 {
  # There is a directory there, so directory listing worked
  v = eregmatch(pattern: '<A HREF="([^"]+.php)">', string:res);
  if (isnull(v)) return;
  req = http_get(item:string(path, "/attachments/", v[1]), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) return(0);
  if ("PHP Shell" >< res ||
    "<input type = 'text' name = 'cmd' value = '' size = '75'>" >< res )
	{
	 security_hole(port: port);
  	 exit(0);
	}
 }
}

foreach dir ( cgi_dirs() ) check_dir(path:dir);

