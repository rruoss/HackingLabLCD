###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_onboard_admin_52862.nasl 11 2013-10-27 10:12:02Z jan $
#
# HP Onboard Administrator Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103795";
CPE = "cpe:/a:hp:onboard_administrator";

tag_insight = "HP Onboard Administrator is prone to:
1. A URI-redirection vulnerability
2. An information-disclosure vulnerability
3. A security-bypass vulnerability";

tag_impact = "An attacker may exploit these issues to obtain sensitive information,
bypass certain security restrictions, and redirect a user to a
potentially malicious site; this may aid in phishing attacks.";

tag_affected = "HP Onboard Administrator (OA) before 3.50";

tag_summary = "HP Onboard Administrator is prone to multiple security vulnerabilities.";
tag_solution = "Updates are available. Please see the references for more information.";
tag_vuldetect = "Check if HP Onboard Administrator version is < 3.50";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(52862);
 script_cve_id("CVE-2012-0128","CVE-2012-0129","CVE-2012-0130");
 script_tag(name:"cvss_base", value:"7.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 11 $");

 script_name("HP Onboard Administrator Multiple Security Vulnerabilities");

 desc = "
Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Impact:
" + tag_impact + "

Affected Software/OS:
" + tag_affected + "

Solution:
" + tag_solution;

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52862");
 script_xref(name:"URL", value:"http://h18004.www1.hp.com/products/blades/components/onboard/index.html?jumpid=reg_R1002_USEN");
 script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03263573");
 
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-10-01 11:28:03 +0200 (Tue, 01 Oct 2013)");
 script_description(desc);
 script_summary("Determine if HP Onboard Administrator version is < 3.50");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_hp_onboard_administrator_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)) {

  if(version_is_less(version: vers, test_version: "3.50")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);
