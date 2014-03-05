# OpenVAS Vulnerability Test
# $Id: invision_power_top_site_sql_injection.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Invision Power Top Site List SQL Injection
#
# Authors:
# Noam Rathaus
# Changes by rd:
# - Use the HTTP api instead of hardcoding HTTP requests
# - changed the description
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
tag_summary = "The remote host is running 'Invision Power Top Site List', a site ranking
script written in PHP.

There is a SQL injection vulnerability in this CGI suite, due to a lack
of user-input sanitizing, which may allow an attacker to execute arbitrary
SQL commands on this host, and therefore gain the control of the database
of this site.";

tag_solution = "Upgrade to the latest version of this CGI suite";

# From: JeiAr [security@gulftech.org]
# Subject: Invision Power Top Site List SQL Inection
# Date: Monday 15/12/2003 23:38

if(description)
{
  script_id(11956);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9229);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
 
  name = "Invision Power Top Site List SQL Injection";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);
 
  summary = "Detect Invision Power Top Site List SQL Injection";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");

  family = "General";
  script_family(family);
  script_dependencies("find_service.nasl", "http_version.nasl");
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

if (! get_port_state(port) ) exit(0);
if (! can_host_php(port:port) ) exit(0);

function check_dir(path)
{
  req = http_get(item:string(path, "/index.php?offset=[%20Problem%20Here%20]"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
 if (egrep(pattern:"syntax to use near '\[ Problem Here \]", string:res))
 {
  security_hole(port);
  exit(0);
 }
}


foreach dir (cgi_dirs())
{
 check_dir(path:dir);
}

