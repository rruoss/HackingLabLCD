###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_dos_vuln_sep13_win.nasl 31865 2013-09-27 10:45:37Z sep$
#
# Wireshark Denial of Service Vulnerability Sep13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

CPE = "cpe:/a:wireshark:wireshark";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804018";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-5717");
  script_bugtraq_id(62322);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-27 10:45:37 +0530 (Fri, 27 Sep 2013)");
  script_name("Wireshark Denial of Service Vulnerability Sep13 (Windows)");

  tag_summary =
"This host is installed with Wireshark and is prone to denial of service
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to an error in the Bluetooth HCI ACL dissector (dissectors/packet
-bthci_acl.c)";

  tag_impact =
"Successful exploitation will allow attackers to cause a DoS (Denial of Service)
and potentially compromise a vulnerable system.

Impact Level: System/Application";

  tag_affected =
"Wireshark version 1.10.x before 1.10.2 on Windows";

  tag_solution =
"Upgrade to Wireshark version 1.10.2 or later,
For updates refer to http://www.wireshark.org/download";

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
  script_xref(name : "URL" , value : "http://www.osvdb.com/97217");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54765");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2013-55.html");
  script_summary("Check for the vulnerable version of Wireshark on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
sharkVer = "";

## Get version
if(!sharkVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

# Check for vulnerable version
if(sharkVer  =~ "^(1\.10)")
{
  if(version_is_less(version:sharkVer, test_version:"1.10.2"))
  {
    security_warning(0);
    exit(0);
  }
}
