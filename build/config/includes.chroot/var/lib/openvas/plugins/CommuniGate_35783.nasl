###############################################################################
# OpenVAS Vulnerability Test
# $Id: CommuniGate_35783.nasl 15 2013-10-27 12:49:54Z jan $
#
# CommuniGate Pro Web Mail URI Parsing HTML Injection Vulnerability
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
tag_summary = "CommuniGate Pro is prone to an HTML-injection vulnerability because it
fails to sufficiently sanitize user-supplied input.

Exploiting this issue may allow an attacker to execute HTML and script
code in the context of the affected site, to steal cookie-based
authentication credentials, or to control how the site is rendered to
the user; other attacks are also possible.

Versions prior to CommuniGate Pro 5.2.15 are vulnerable.";

tag_solution = "The vendor released an update to address this issue; please see the
references for more information.";

if (description)
{
 script_id(100242);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-07-26 19:54:54 +0200 (Sun, 26 Jul 2009)");
 script_bugtraq_id(35783);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("CommuniGate Pro Web Mail URI Parsing HTML Injection Vulnerability");

desc = "

 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution + "
";


 script_description(desc);
 script_summary("Determine if CommuniGate Pro Version is < 5.2.15");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/35783");
 script_xref(name : "URL" , value : "http://www.stalker.com/CommuniGatePro/default.html");
 script_xref(name : "URL" , value : "http://www.communigate.com/cgatepro/History52.html");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/505211");
 exit(0);
}

     
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

version = get_http_banner(port: port);
if(!version)exit(0);
if(!matches = eregmatch(string:version, pattern:"Server: CommuniGatePro/([0-9.]+)"))exit(0);

vers = matches[1];

if(!isnull(vers)) {

  if(version_is_less(version: vers, test_version: "5.2.15")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);
