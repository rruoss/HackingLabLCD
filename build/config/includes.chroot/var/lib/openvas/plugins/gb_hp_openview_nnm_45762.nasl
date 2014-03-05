###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_openview_nnm_45762.nasl 13 2013-10-27 12:16:33Z jan $
#
# HP OpenView Network Node Manager Multiple Remote Code Execution Vulnerabilities
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
tag_summary = "HP OpenView Network Node Manager is prone to multiple remote code-
execution vulnerabilities.

Successful exploits may allow an attacker to execute arbitrary code
with the privileges of the user running the application's webserver.
Failed exploit attempts will likely result in denial-of-service
conditions.

OpenView Network Node Manager 7.51 and 7.53 are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(103026);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-01-13 13:28:59 +0100 (Thu, 13 Jan 2011)");
 script_bugtraq_id(45762);
 script_cve_id("CVE-2011-0261","CVE-2011-0262","CVE-2011-0263","CVE-2011-0264","CVE-2011-0265","CVE-2011-0266","CVE-2011-0267","CVE-2011-0268","CVE-2011-0269","CVE-2011-0270","CVE-2011-0271");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("HP OpenView Network Node Manager Multiple Remote Code Execution Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45762");
 script_xref(name : "URL" , value : "http://openview.hp.com/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/515628");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-003/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-004/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-005/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-006/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-007/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-008/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-009/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-010/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-011/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-012/");

 script_tag(name:"risk_factor", value:"Critical");
 script_description(desc);
 script_summary("Determine if installed HP OpenView Network Node Manager version is 7.51 or 7.53");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("secpod_hp_openview_nnm_detect.nasl");
 script_require_ports(7510);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");

nnmPort = 7510;
if(!get_port_state(nnmPort)){
  exit(0);
}

nnmVer = get_kb_item(string("www/", nnmPort, "/HP/OVNNM/Ver"));
if(nnmVer != NULL)
{
  if(version_is_equal(version:nnmVer, test_version:"B.07.51") ||
     version_is_equal(version:nnmVer, test_version:"B.07.53")){
       security_hole(port:nnmPort);
       exit(0);
  }
}

exit(0);

