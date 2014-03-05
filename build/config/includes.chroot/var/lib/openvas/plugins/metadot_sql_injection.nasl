# OpenVAS Vulnerability Test
# $Id: metadot_sql_injection.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Multiple MetaDot Vulnerabilities
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
tag_summary = "The remote host is running Metadot, a popular open source portal software. 


Multiple vulnerabilities have been found in this product, which may allow a 
malicious user to inject arbitrary SQL commands, reveal valuable information 
about the server and perform Cross Site Scripting attacks.";

tag_solution = "Upgrade to the latest version of Metadot";

# From: JeiAr [security@gulftech.org]
# Subject: Multiple MetaDot Vulnerabilities [ All Versions ]
# Date: Friday 16/01/2004 03:11

if(description)
{
  script_id(12024);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9439);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  name = "Multiple MetaDot Vulnerabilities";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);
 
  summary = "Detect MetaDot SQL Injection";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");

  family = "Web application abuses";
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

function check_dir(path)
{
 req = http_get(item:string(path, "/metadot/index.pl?isa=Session&op=auto_login&new_user=&key='[foo]"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 find = "DBAccess::sqlSelect('DBAccess', 'uid', 'session', 'sessionid=\'\'[foo]\'')";
 if ( find >< res )
 {
  security_hole(port);
  exit(0);
 }
}


foreach dir (cgi_dirs()) check_dir(path:dir);
