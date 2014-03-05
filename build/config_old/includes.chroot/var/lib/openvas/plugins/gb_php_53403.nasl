###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_53403.nasl 12 2013-10-27 11:15:33Z jan $
#
# PHP  Directory Traversal Vulnerability
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
tag_summary = "PHP is prone to a directory-traversal vulnerability because it fails
to properly sanitize user-supplied input.

Remote attackers can use specially crafted requests with directory-
traversal sequences ('../') to retrieve, corrupt or upload arbitrary
files in the context of the application.

Exploiting this issue may allow an attacker to retrieve, corrupt or
upload arbitrary files at arbitrary locations that could aid in
further attacks.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103486);
 script_bugtraq_id(53403);
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
 script_cve_id("CVE-2012-1172");
 script_version ("$Revision: 12 $");

 script_name("PHP  Directory Traversal Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53403");
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=799187");
 script_xref(name : "URL" , value : "http://www.php.net/archive/2012.php#id2012-04-26-1");
 script_xref(name : "URL" , value : "http://www.php.net/");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-05-08 11:25:16 +0200 (Tue, 08 May 2012)");
 script_description(desc);
 script_summary("Determine if installed php version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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

  if(version_in_range(version:vers, test_version:"5.4", test_version2:"5.4.0") ||
     version_in_range(version:vers, test_version:"5.3", test_version2:"5.3.10")) {
  
     security_hole(port:port);
     exit(0);
  }

}  

exit(0);
