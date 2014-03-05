###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_epm_sbe_bof_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Symantec Endpoint Protection Center (SPC) Small Business Edition Buffer Overflow Vulnerability
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

if (description)
{
  script_id(803883);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1612");
  script_bugtraq_id(60542);
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-29 19:01:42 +0530 (Thu, 29 Aug 2013)");
  script_name("Symantec Endpoint Protection Center (SPC) Small Business Edition Buffer Overflow Vulnerability");

  tag_summary =
"The host is installed with Symantec Endpoint Protection Manager and is prone
to buffer overflow vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to a boundary error within secars.dll.";

  tag_impact =
"Successful exploitation will allow attackers to cause a buffer overflow via
the web based management console.";

  tag_affected =
"Symantec Endpoint Protection Center (SPC) Small Business Edition version
12.1.x before 12.1.3";

  tag_solution =
"Upgrade to version 12.1.3 or later,
For updates refer to http://www.symantec.com";

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
  script_xref(name : "URL" , value : "http://www.osvdb.com/94421");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53864");
  script_xref(name : "URL" , value : "http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;suid=20130618_00");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_summary("Check for the vulnerable version of Symantec Endpoint Protection");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/SEP/SmallBusiness", "Symantec/Endpoint/Protection");
  exit(0);
}


include("version_func.inc");

## Variable Initialisation
sepVer = "";

## Get Symantec Endpoint Protection version
sepVer = get_kb_item("Symantec/Endpoint/Protection");
if(!sepVer){
 exit(0);
}

## Check for Symantec Endpoint Protection versions
if(sepVer && sepVer =~ "^12.1")
{
  if(version_is_less(version:sepVer, test_version:"12.1.3"))
  {
    security_hole(0);
    exit(0);
  }
}
