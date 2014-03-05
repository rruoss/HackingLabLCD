###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_53145.nasl 12 2013-10-27 11:15:33Z jan $
#
# ownCloud Multiple Input Validation Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
tag_summary = "ownCloud is prone to a URI open-redirection vulnerability,
multiple cross-site scripting vulnerabilities and multiple HTML-
injection vulnerabilities because it fails to properly sanitize
user-supplied input.

An attacker could leverage the cross-site scripting issues to execute
arbitrary script code in the browser of an unsuspecting user in the
context of the affected site. This may let the attacker steal cookie-
based authentication credentials and launch other attacks.

Attacker-supplied HTML and script code would run in the context of the
affected browser, potentially allowing the attacker to steal cookie-
based authentication credentials or control how the site is rendered
to the user. Other attacks are also possible.

Successful exploits may redirect a user to a potentially malicious
site; this may aid in phishing attacks.

ownCloud 3.0.0 is vulnerable; other versions may also be affected.";

tag_solution = "Updates are available. Please see the reference for more details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103473";
CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 12 $");
 script_bugtraq_id(53145);
 script_cve_id("CVE-2012-2269", "CVE-2012-2270", "CVE-2012-2397", "CVE-2012-2398");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 12 $");
 script_name("ownCloud Multiple Input Validation Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53145");
 script_xref(name : "URL" , value : "http://owncloud.org/");
 script_xref(name : "URL" , value : "http://www.tele-consulting.com/advisories/TC-SA-2012-01.txt");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/522397");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-04-19 12:17:59 +0200 (Thu, 19 Apr 2012)");
 script_description(desc);
 script_summary("Determine if ownCloud is prone to XSS");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_owncloud_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("owncloud/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

url = string(dir, '/index.php?redirect_url=1"><script>alert(/openvas-xss-test/)</script><l="'); 

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>", check_header:TRUE, extra_check:"Powered by ownCloud")) {
     
  security_hole(port:port);
  exit(0);

}

exit(0);

