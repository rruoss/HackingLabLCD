###############################################################################
# OpenVAS Vulnerability Test
# $Id: Pixie_cms_sql_injection_xss.nasl 15 2013-10-27 12:49:54Z jan $
#
# Pixie CMS SQL Injection and Cross Site Scripting Vulnerabilities
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
tag_summary = "Pixie CMS is prone to an SQL-injection vulnerability and a cross-site
 scripting vulnerability because it fails to sufficiently sanitize
 user-supplied data.

 Exploiting these issues could allow an attacker to steal cookie-based
 authentication credentials, compromise the application, access or
 modify data, or exploit latent vulnerabilities in the underlying
 database. 

 See Also:
  http://www.securityfocus.com/bid/34189";


if (description)
{
 script_id(100066);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-20 13:11:29 +0100 (Fri, 20 Mar 2009)");
 script_cve_id("CVE-2009-1066");
 script_bugtraq_id(34189);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 desc = "

 Summary:
 " + tag_summary;

 script_name("Pixie CMS SQL Injection and Cross Site Scripting Vulnerabilities");
 script_description(desc);
 script_summary("Determine if Pixie CMS is prone to SQL Injection and Cross Site Scripting vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
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
include("version_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

dir = make_list("/cms",cgi_dirs());

foreach d (dir)
{ 
 
 url = string(d, "/index.php?s=blog&m=permalink&x=%22%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E");

 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;

 if (
     (egrep(pattern: "Pixie Powered", string: buf) || (egrep( pattern:"Set-Cookie: bb2_screener_", string: buf))) &&
      egrep(pattern:".*<script>alert\(document.cookie\)</script>.*", string: buf, icase: true) )
 { 
     security_hole(port:port,data:desc);
     exit(0);
 }
}
 
exit(0);
