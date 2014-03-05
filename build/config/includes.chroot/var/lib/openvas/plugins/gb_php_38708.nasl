###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_38708.nasl 14 2013-10-27 12:33:37Z jan $
#
# PHP xmlrpc Extension Multiple Remote Denial of Service Vulnerabilities
#
# Authors:
# Michael Meyer
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
tag_summary = "PHP's xmlrpc extension library is prone to multiple denial-of-
service vulnerabilities because it fails to properly handle crafted
XML-RPC requests.

Exploiting these issues allows remote attackers to cause denial-of-
service conditions in the context of an application using the
vulnerable library.

PHP 5.3.1 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100529);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-15 13:03:19 +0100 (Mon, 15 Mar 2010)");
 script_bugtraq_id(38708);
 script_cve_id("CVE-2010-0397");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("PHP xmlrpc Extension Multiple Remote Denial of Service Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38708");
 script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=573573");
 script_xref(name : "URL" , value : "http://permalink.gmane.org/gmane.comp.security.oss.general/2673");
 script_xref(name : "URL" , value : "http://www.php.net/");

 script_description(desc);
 script_summary("Determine if php version is 5.3.1");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_php_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("php/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("global_settings.inc");

## This nvt is prone to FP
if(report_paranoia < 2){
  exit(0);
}

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(!vers = get_kb_item(string("www/", port, "/PHP")))exit(0);
if(!isnull(vers)) {

  if(version_is_equal(version: vers, test_version: "5.3.1")) {
    security_warning(port:port);
    exit(0);
  }
}

exit(0);
