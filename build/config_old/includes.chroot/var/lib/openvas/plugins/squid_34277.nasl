###############################################################################
# OpenVAS Vulnerability Test
# $Id: squid_34277.nasl 15 2013-10-27 12:49:54Z jan $
#
# Squid Proxy Cache ICAP Adaptation Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "According to its version number, the remote version of Squid
  is prone to a to a remote denial-of-service vulnerability because
  the proxy server fails to adequately bounds-check user-supplied data
  before copying it to an insufficiently sized buffer.

  Successfully exploiting this issue allows remote attackers to
  consume excessive memory, resulting in a denial-of-service
  condition.

  Note that to exploit this issue, an attacker must be a legitimate
  client user of the proxy.

  The Squid 3.x branch is vulnerable.";

tag_solution = "Upgrade to newer Version if available.";


if (description)
{
 script_id(100084);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-28 19:13:00 +0100 (Sat, 28 Mar 2009)");
 script_bugtraq_id(34277);
 script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Squid Proxy Cache ICAP Adaptation Denial of Service Vulnerability");
 desc = "

 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 script_summary("Determine if version of Squid is < 3.1.6");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("http_version.nasl","proxy_use.nasl");
 script_require_ports("Services/http_proxy", 3128, 8080, 6588, 8000);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34277");
 script_xref(name : "URL" , value : "http://www.squid-cache.org/");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("version_func.inc");

port = get_kb_item("Services/http_proxy");
if (!get_port_state(port)) exit(0);
if(!get_kb_item("www/squid"))exit(0);
if(!VIA = get_kb_item(string("Proxy/" + port  + "/via")))exit(0);

version = eregmatch(string:VIA, pattern:"^.*\(squid/([0-9.]+)[STABLE|PRE]*([0-9]*)\)");
if(isnull(version[1]))exit(0);

	ver = version[1];
	if(version[2])ver = string(ver,version[2]);
	if (version_in_range(version:ver, test_version:"3", test_version2:"3.1.5"))
	 {
	   security_warning(port:port);
	   exit(0);
	}

exit(0);
