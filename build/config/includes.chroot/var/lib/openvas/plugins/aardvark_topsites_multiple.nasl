# OpenVAS Vulnerability Test
# $Id: aardvark_topsites_multiple.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Aardvark Topsites Multiple Vulnerabilities
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
tag_summary = "Aardvark Topsites is a popular free PHP Topsites script.
Multiple vulnerabilities have been found in the product allowing remote
attacker to disclosure sensitive information about the server and inject
malicious SQL statements.";

tag_solution = "Upgrade to version 4.1.1 or newer.";

# From: JeiAr [security@gulftech.org]
# Subject: Aardvark Topsites 4.1.0 Vulnerabilities
# Date: Tuesday 16/12/2003 04:58

if(description)
{
  script_id(11957);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9231);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  name =  "Aardvark Topsites Multiple Vulnerabilities";
  script_name(name);

  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);
 
  summary = "Detect Aardvark Topsites version";
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

if ( ! can_host_php(port:port) ) exit(0);

function check_dir(path)
{
  req = http_get(item:string(path, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
  if (egrep(pattern:"Aardvark Topsites PHP.* (4\.1\.0|4\.0\.|[0-3]\..*)", string:res))
  {
   security_hole(port);
   exit(0);
  }
}

foreach dir (cgi_dirs())
{
 check_dir(path:dir);
}

