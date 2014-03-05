# OpenVAS Vulnerability Test
# $Id: knowledge_builder_code_execution.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Remote Code Execution in Knowledge Builder
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
tag_summary = "KnowledgeBuilder is a feature-packed knowledge base solution CGI suite. 

A vulnerability in this product may allow a remote attacker to execute 
arbitrary commands on this host.";

tag_solution = "Upgrade to the latest version or disable this CGI altogether";

# From: Zero_X www.lobnan.de Team [zero-x@linuxmail.org]
# Subject: Remote Code Execution in Knowledge Builder
# Date: Wednesday 24/12/2003 15:45

if(description)
{
  script_id(11959);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  name = "Remote Code Execution in Knowledge Builder";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);
 
  summary = "Detect Knowledge Builder Code Execution";
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

debug = 0;

port = get_http_port(default:80);

if (! get_port_state(port) ) exit(0);
if (! can_host_php(port:port) ) exit(0);

function check_dir(path)
{
 req = http_get(item:string(path, "/index.php?page=http://xxxxxxxxxxxxx/openvas"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 find = string("operation error");
 find_alt = string("getaddrinfo failed");

 if (find >< res || find_alt >< res )
 {
  req = http_get(item:string(path, "/index.php?page=index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
  if ( find >< res || find_alt >< res ) exit(0);
  security_hole(port);
  exit(0);
 }
}

foreach dir (make_list("/kb", cgi_dirs())) check_dir(path:dir);

