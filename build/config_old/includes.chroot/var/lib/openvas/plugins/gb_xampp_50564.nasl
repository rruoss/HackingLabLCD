###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xampp_50564.nasl 13 2013-10-27 12:16:33Z jan $
#
# XAMPP 'PHP_SELF' Variable Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "XAMPP is prone to multiple cross-site scripting vulnerabilities
because it fails to sufficiently sanitize user-supplied data.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and launch other attacks.

These issues affect XAMPP 1.7.7 for Windows.";


if (description)
{
 script_id(103336);
 script_bugtraq_id(50564);
 script_version ("$Revision: 13 $");
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_name("XAMPP 'PHP_SELF' Variable Multiple Cross Site Scripting Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50564");
 script_xref(name : "URL" , value : "http://www.apachefriends.org/en/xampp.html");
 script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5054.php");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-11-08 09:38:06 +0100 (Tue, 08 Nov 2011)");
 script_description(desc);
 script_summary("Determine if installed XAMPP is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("os_fingerprint.nasl","secpod_xampp_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if (host_runs("windows") != "yes")exit(0);
if (! xamppVer = get_kb_item("www/" + port + "/XAMPP"))exit(0);

url = string('/xampp/perlinfo.pl/"><script>alert(/openvas-xss-test/)</script>'); 

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>",check_header:TRUE)) {
     
  security_warning(port:port);
  exit(0);

}

exit(0);
