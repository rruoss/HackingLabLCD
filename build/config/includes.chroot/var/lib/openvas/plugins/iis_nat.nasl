# OpenVAS Vulnerability Test
# $Id: iis_nat.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Private IP address leaked in HTTP headers
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
# Modified by Paul Johnston for Westpoint Ltd <paul@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com, 2003 Westpoint Ltd
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
tag_summary = "This web server leaks a private IP address through its HTTP headers.

Description :

This may expose internal IP addresses that are usually hidden or masked
behind a Network Address Translation (NAT) Firewall or proxy server.

There is a known issue with IIS 4.0 doing this in its default configuration.";

 desc = "
 Summary:
 " + tag_summary;


if(description)
{
 script_id(10759);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1499);
 script_cve_id("CVE-2000-0649");
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Private IP address leaked in HTTP headers";
 script_name(name);

 script_description(desc);

 summary = "Checks for private IP addresses in HTTP headers";

 script_summary(summary);

 script_category(ACT_GATHER_INFO);


 script_copyright("This script is Copyright (C) 2001 Alert4Web.com, 2003 Westpoint Ltd");
 family = "General";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_xref(name : "URL" , value : "http://support.microsoft.com/support/kb/articles/Q218/1/80.ASP");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("global_settings.inc");

if ( report_paranoia == 0 )
{
 if ( ! all_addr_public )  exit(0);
}
else if ( all_addr_private ) exit(0);

port = get_http_port(default:80);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

#
# Craft our own HTTP/1.0 request for the server banner.
# Note: HTTP/1.1 is rarely useful for detecting this flaw.
#
soc = http_open_socket(port);
if(!soc) exit(0);
send(socket:soc, data:string("GET / HTTP/1.0", "\r\n",
                             "Host: ", get_host_name(), "\r\n"));
banner = http_recv_headers2(socket:soc);
http_close_socket(soc);

#
# Check for private IP addresses in the banner
# Ranges are: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
#
private_ip = eregmatch(pattern:"([^12]10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})", string:banner);
if(!isnull(private_ip) && ! egrep(pattern:"Oracle.*/10\.", string:banner) )
{
 report = string (desc,
		"\n\nPlugin output :\n\n",
		"This web server leaks the following private IP address : ",
		private_ip[0]);

 security_warning (port:port, data:report);
}
