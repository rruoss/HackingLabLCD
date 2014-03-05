###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bugzilla_42275.nasl 14 2013-10-27 12:33:37Z jan $
#
# Bugzilla Multiple Vulnerabilities
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
tag_summary = "Bugzilla is prone to the following vulnerabilities:

1. A security bypass issue.
2. Multiple information-disclosure vulnerabilities.
3. A denial-of-service vulnerability.

Successfully exploiting these issues may allow an attacker to
bypass certain security restrictions, obtain sensitive information
or cause the affected application to crash, denying service to
legitimate users.

The following versions are vulnerable:

4.x and 3.2.x versions prior to 3.2.8,
4.1.x and 3.4.x versions prior to 3.4.8.
4.2.x and 3.6.x versions prior to 3.6.2.
4.3.x versions prior to 3.7.3.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100749);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-08-09 13:36:05 +0200 (Mon, 09 Aug 2010)");
 script_bugtraq_id(42275);
 script_cve_id("CVE-2010-2756","CVE-2010-2757","CVE-2010-2758","CVE-2010-2759");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

 script_name("Bugzilla Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42275");
 script_xref(name : "URL" , value : "http://www.bugzilla.org/security/3.2.7/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed Bugzilla version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("bugzilla_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

vers = get_version_from_kb(port:port, app:"bugzilla/version");
if(!vers){
 exit(0);
}

if(version_in_range(version:vers, test_version: "2", test_version2:"3.2.7")   ||
   version_in_range(version:vers, test_version: "3.3", test_version2:"3.4.7") ||
   version_in_range(version:vers, test_version: "3.5", test_version2:"3.6.1") ||
   version_in_range(version:vers, test_version: "3.7", test_version2:"3.7.2")){
     security_hole(port:port);
     exit(0);
}

exit(0);