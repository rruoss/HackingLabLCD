###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_openview_nnm_50471.nasl 13 2013-10-27 12:16:33Z jan $
#
# HP OpenView Network Node Manager Multiple Remote Code Execution Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "HP OpenView Network Node Manager (NNM) is prone to multiple remote
code-execution vulnerabilities because it fails to sanitize user-
supplied data.

An attacker can exploit these issues to execute arbitrary code with
the privileges of the user running the affected application.
Successful exploits will compromise the affected application and
possibly the underlying computer.

These issues affects NNM 7.51, v7.53 running on HP-UX, Linux, Solaris,
and Windows; other versions and platforms may also be affected.";

tag_solution = "Updates are available; please contact the vendor for more information.";

if (description)
{
 script_id(103364);
 script_bugtraq_id(50471);
 script_cve_id("CVE-2011-3166","CVE-2011-3167");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 13 $");

 script_name("HP OpenView Network Node Manager Multiple Remote Code Execution Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50471");
 script_xref(name : "URL" , value : "http://www.openview.hp.com/products/nnm/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/520349");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-12-14 09:14:18 +0100 (Wed, 14 Dec 2011)");
 script_description(desc);
 script_summary("Determine if installed HP OpenView Network Node Manager version is vulnerable");
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
