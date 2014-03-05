###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_onboard_admin_sec_bypass_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# HP Onboard Administrator Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803767";
CPE = "cpe:/a:hp:onboard_administrator";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2011-3155");
  script_bugtraq_id(50053);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-03 17:49:51 +0530 (Thu, 03 Oct 2013)");
  script_name("HP Onboard Administrator Security Bypass Vulnerability");

 tag_summary =
"This host is running HP Onboard Administrator and is prone to security bypass
vulnerability.";

  tag_vuldetect =
"Get the installed version of HP Onboard Administrator with the help of detect
NVT and check the version is vulnerable or not.";

  tag_insight =
"The flaw is due to an unspecified error.";

  tag_impact =
"Successful exploitation will allow attacker to bypass intended access
restrictions via unknown vectors.

Impact Level: Application";

  tag_affected =
"HP Onboard Administrator (OA) versions 3.21 through 3.31";

  tag_solution =
"Upgrade to HP Onboard Administrator 3.32 or later,
http://www8.hp.com/us/en/products/oas/product-detail.html?oid=3188465";

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

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.org/76280");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46385");
  script_xref(name : "URL" , value : "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03048779");
  script_summary("Check the vulnerable version of HP Onboard Administrator");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_onboard_administrator_detect.nasl");
  script_mandatory_keys("hp_onboard_admin/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
hpobVer = "";
hpobPort = 0;

## Get HTTP Port
hpobPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!hpobPort){
  exit(0);
}

## Get Cisco Content Security Management Appliance (SMA) version
if(!hpobVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:hpobPort)){
  exit(0);
}

## check the vulnerable versions
if("unknown" >!< hpobVer && hpobVer =~ "^3\.")
{
  if(version_in_range(version:hpobVer, test_version:"3.21", test_version2: "3.31"))
  {
    security_hole(hpobPort);
    exit(0);
  }
}
