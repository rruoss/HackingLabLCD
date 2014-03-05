###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_syndeocms_47018.nasl 13 2013-10-27 12:16:33Z jan $
#
# SyndeoCMS Multiple Cross Site Scripting and SQL Injection Vulnerabilities
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
tag_summary = "SyndeoCMS is prone to multiple cross-site scripting vulnerabilities
and an SQL-injection vulnerability because it fails to sufficiently
sanitize user-supplied data.

Exploiting these issues could allow an attacker to steal cookie-
based authentication credentials, compromise the application,
access or modify data, or exploit latent vulnerabilities in the
underlying database.

SyndeoCMS 2.8.02 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103127);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-03-25 13:20:06 +0100 (Fri, 25 Mar 2011)");
 script_bugtraq_id(47018);

 script_name("SyndeoCMS Multiple Cross Site Scripting and SQL Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/47018");
 script_xref(name : "URL" , value : "http://www.syndeocms.org/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/517160");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/517172");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/517162");

 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if SyndeoCMS is prone to multiple cross-site scripting vulnerabilities");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_SyndeoCMS_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port, app:"syndeocms"))exit(0);

url = string(dir,"/starnet/addons/scroll_page.php?speed=--></script></head><script>alert('openvas-xss-test');</script>"); 

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\('openvas-xss-test'\);</script>",check_header:TRUE)) {
     
  security_hole(port:port);
  exit(0);

}

exit(0);
