# OpenVAS Vulnerability Test
# $Id: ezcontents_code_execution.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Remote Code Execution in ezContents
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
tag_summary = "ezContents is an Open-Source website content management system based
on PHP and MySQL. Features include maintaining menus and sub-menus,
adding authors that write contents, permissions, workflow, and
layout possibilities for the entire look of the site by simple use of settings.

The product has been found to contain a vulnerability that would allow
a remote attacker to cause the PHP script to include an external PHP
file and execute its content. This would allow an attacker to cause
the server to execute arbitrary code.";

# From: Zero_X www.lobnan.de Team [zero-x@linuxmail.org]
# Subject: Remote Code Execution in ezContents
# Date: Saturday 10/01/2004 19:14

if(description)
{
  script_id(12021);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0070");
  script_bugtraq_id(9396);
  script_xref(name:"OSVDB", value:"6878");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 
  name = "Remote Code Execution in ezContents";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
 
  summary = "Detect ezContents Code Execution";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");

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

port = get_http_port(default:80);

if( ! get_port_state(port) ) exit(0);
if( ! can_host_php(port:port) ) exit(0);

function check_dir(path)
{
 req = http_get(item:string(path, "/module.php?link=http://xxxx./index.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( egrep(pattern:"main.*'http://xxxx\./index\.php'.*modules\.php",
	    string:res))
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check_dir(path:dir);
}
