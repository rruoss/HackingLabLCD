# OpenVAS Vulnerability Test
# $Id: propfind_internal_ip.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Private IP address Leaked using the PROPFIND method
#
# Authors:
# Anthony R. Plastino III <tplastino@sses.net>
#
# Copyright:
# Copyright (C) 2004 Sword & Shield Enterprise Security, Inc.
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
tag_summary = "The remote web server leaks a private IP address through the WebDAV interface.  If this 
web server is behind a Network Address Translation (NAT) firewall or proxy server, then 
the internal IP addressing scheme has been leaked.

This is typical of IIS 5.0 installations that are not configured properly.

Detail: http://www.nextgenss.com/papers/iisrconfig.pdf";

tag_solution = "see http://support.microsoft.com/default.aspx?scid=KB%3BEN-US%3BQ218180&ID=KB%3BEN-US%3BQ218180";

if(description)
{
  script_id(12113);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2002-0422");
  name = "Private IP address Leaked using the PROPFIND method";
  script_name(name);

  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);

  summary = "Checks for private IP addresses in PROPFIND response";
  script_summary(summary);

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) Sword & Shield Enterprise Security, Inc., 2004");
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

# 
# Now the code
#

if ( egrep(pattern:"(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})", string:string(get_host_ip()))) exit(0);

include("http_func.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if (sig && "IIS" >!< sig) exit(0);


#
# Build the custome HTTP/1.1 request for the server to respond to
#

soc = http_open_socket(port);
if ( ! soc ) exit(0);
send(socket:soc, data:string("PROPFIND / HTTP/1.0\r\n","Host: ", get_host_name(), "\r\nContent-Length: 0\r\n\r\n"));
headers = http_recv_headers2(socket:soc);
stuff = http_recv_body(socket:soc, headers:headers);
http_close_socket(soc);

# 
# now check for RFC 1918 addressing in the returned data - not necessarily in the header
# Ranges are: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
#
private_ip = eregmatch(pattern:"(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})", string:stuff);
if(!isnull(private_ip) && private_ip !~ "Oracle.*/10\.")
{
  report = string("
The remote web server leaks a private IP address through the WebDAV interface.
If this web server is behind a Network Address Translation (NAT) firewall or proxy 
server, then the internal IP addressing scheme has been leaked.
That address is: ", private_ip[0], "
This is typical of IIS 5.0 installations that are not configured properly.

See also : http://www.nextgenss.com/papers/iisrconfig.pdf
Solution : http://support.microsoft.com/default.aspx?scid=KB%3BEN-US%3BQ218180&ID=KB%3BEN-US%3BQ218180");

  security_warning(port:port, data:report);
}
