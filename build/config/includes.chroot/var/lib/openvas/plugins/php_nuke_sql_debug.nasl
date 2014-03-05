# OpenVAS Vulnerability Test
# $Id: php_nuke_sql_debug.nasl 17 2013-10-27 14:01:43Z jan $
# Description: PHP-Nuke sql_debug Information Disclosure
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
# Updated: 2009/04/24
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2002 Alert4Web.com
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
tag_solution = "Add '$sql_debug = 0;' in config.php.";
tag_summary = "In PHP-Nuke, the sql_layer.php script contains a debugging
feature that may be used by attackers to disclose sensitive information about
all SQL queries.  Access to the debugging feature is not restricted to
administrators.";

if(description)
{
  script_id(10856);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-2032");
  script_bugtraq_id(3906);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("PHP-Nuke sql_debug Information Disclosure");
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);
  script_summary("Make a request like http://www.example.com/?sql_debug=1");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2002 Alert4Web.com");
  script_dependencies("secpod_php_nuke_detect.nasl");
  script_require_ports("Services/www", 80);
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
include("version_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port)){
  exit(0);
}

phpVer =get_kb_item("www/" + port + "/php-nuke");
phpVer = eregmatch(pattern:"(.*) under (.*)", string:phpVer);

if(phpVer[1] == NULL && phpVer[2] == NULL){
   exit(0);
}

version=phpVer[1];
dir = phpVer[2];

if(!safe_checks())
{
  req = http_get(item:dir + "/?sql_debug=1", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if(res == NULL){
    exit(0);
  }
  if("SQL query: " >< res)
  {
    security_warning(port:port);
    exit(0);
  }
}

if(version_is_less_equal(version:version,test_version:"5.4")){
      security_warning(port);
      exit(0);
}
