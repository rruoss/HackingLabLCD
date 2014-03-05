###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cups_web_interface_mult_vulnerabilities.nasl 14 2013-10-27 12:33:37Z jan $
#
# CUPS Web Interface Multiple Vulnerabilities
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
tag_summary = "CUPS Web Interface is prone to Multiple Vulnerabilities.

1.
A remote information-disclosure vulnerability. This
issue affects the CUPS web interface component.

Remote attackers can exploit this issue to obtain sensitive
information that may lead to further attacks.

2.
A cross-site request-forgery vulnerability.

Attackers can exploit this issue to perform certain administrative
actions and gain unauthorized access to the affected application.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100687);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-22 12:10:21 +0200 (Tue, 22 Jun 2010)");
 script_bugtraq_id(40897,40889);
 script_cve_id("CVE-2010-1748","CVE-2010-0540");
 script_tag(name:"cvss_base", value:"6.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

 script_name("CUPS Web Interface Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/40897");
 script_xref(name : "URL" , value : "http://cups.org/articles.php?L596");
 script_xref(name : "URL" , value : "http://www.apple.com/macosx/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if Cups version is < 1.4.4");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_cups_detect.nasl");
 script_require_ports("Services/www", 631);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

cupsPort = get_http_port(default:631);
if(!cupsPort){
  exit(0);
}

cupsVer = get_kb_item("www/"+ cupsPort + "/CUPS");
if(!cupsVer){
  exit(0);
}

if(cupsVer != NULL)
{
  # Check for CUPS version < 1.4.4
  if(version_is_less(version:cupsVer, test_version:"1.4.4")){
    security_hole(port:cupsPort);
  }
}

exit(0);