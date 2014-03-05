###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_winscp_int_overflow_vuln_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# WinSCP Integer Overflow Vulnerability (Windows)
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
tag_impact = "
  Impact Level: System/Application";

CPE = "cpe:/a:winscp:winscp";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803873";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-4852");
  script_bugtraq_id(61599);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-21 13:50:22 +0530 (Wed, 21 Aug 2013)");
  script_name("WinSCP Integer Overflow Vulnerability (Windows)");

  tag_summary =
"The host is installed with WinSCP and is prone to integer overflow
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to improper validation of message lengths in the getstring()
function in sshrsa.c and sshdss.c when handling negative SSH handshake.";

  tag_impact =
"Successful exploitation will allow attackers to cause heap-based buffer
overflows, resulting in a denial of service or potentially allowing the
execution of arbitrary code.";

  tag_affected =
"WinSCP version before 5.1.6 on Windows";

  tag_solution =
"Upgrade to version 5.1.6 or later,
For updates refer to http://winscp.net";

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
  script_xref(name : "URL" , value : "http://www.osvdb.com/95970");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54355");
  script_xref(name : "URL" , value : "http://winscp.net/eng/docs/history#5.1.6");
  script_xref(name : "URL" , value : "http://winscp.net/tracker/show_bug.cgi?id=1017");
  script_summary("Check for the vulnerable version of WinSCP on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_winscp_detect_win.nasl");
  script_mandatory_keys("WinSCP/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Get the version
if(!scpVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check for WinSCP version
if(version_is_less(version:scpVer, test_version:"5.1.6"))
{
  security_hole(0);
  exit(0);
}
