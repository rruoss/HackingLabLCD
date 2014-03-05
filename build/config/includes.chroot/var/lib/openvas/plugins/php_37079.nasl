###############################################################################
# OpenVAS Vulnerability Test
# $Id: php_37079.nasl 15 2013-10-27 12:49:54Z jan $
#
# PHP Versions Prior to 5.3.1 Multiple Vulnerabilities
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
tag_summary = "PHP is prone to multiple security vulnerabilities.

Some of these issues may be exploited to bypass security restrictions
and create arbitrary files or cause denial-of-service conditions. The
impact of the other issues has not been specified. We will update this
BID when more information becomes available.

These issues affect PHP versions prior to 5.3.1.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100359);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-11-23 18:01:08 +0100 (Mon, 23 Nov 2009)");
 script_bugtraq_id(37079);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("PHP Versions Prior to 5.3.1 Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37079");
 script_xref(name : "URL" , value : "http://securityreason.com/securityalert/6601");
 script_xref(name : "URL" , value : "http://securityreason.com/securityalert/6600");
 script_xref(name : "URL" , value : "http://www.php.net/releases/5_3_1.php");
 script_xref(name : "URL" , value : "http://www.php.net/");
 script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2009/Nov/228");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/507982");

 script_description(desc);
 script_summary("Determine if php version is < 5.3.1");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("gb_php_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("php/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
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

  if(version_is_less(version: vers, test_version: "5.3.1")) {
      security_hole(port:port);
      exit(0);
  }
}

exit(0);

