###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_java_mult_unspecified_vuln03_oct13.nasl 33 2013-10-31 15:16:09Z veerendragg $
#
# Oracle Java SE JRE Multiple Unspecified Vulnerabilities-03 Oct 2013 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:oracle:jre";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804119";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 33 $");
  script_cve_id("CVE-2013-5838");
  script_bugtraq_id(63131);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-31 16:16:09 +0100 (Do, 31. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-25 17:35:17 +0530 (Fri, 25 Oct 2013)");
  script_name("Oracle Java SE JRE Multiple Unspecified Vulnerabilities-03 Oct 2013 (Windows)");

  tag_summary =
"This host is installed with Oracle Java SE JRE and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version of Oracle Java SE JRE with the help of detect NVT
and check it is vulnerable or not.";

  tag_insight =
"Unspecified vulnerability exists due to unknown vectors related to Libraries.";

  tag_impact =
"Successful exploitation will allow remote attackers to affect confidentiality,
integrity, and availability via unknown vectors.

Impact Level: System/Application.";

  tag_affected =
"Oracle Java SE 7 update 25 and earlier on Windows";

  tag_solution =
"Apply the patch from below link,
http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html";

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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/55315");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/63131");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html");
  script_summary("Check the vulnerable version of Oracle Java SE on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
jreVer = "";

## Get version
if(!jreVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID))
{
  CPE = "cpe:/a:sun:jre";
  if(!jreVer = get_app_version (cpe:CPE, nvt:SCRIPT_OID)){
    exit(0);
  }
}


if(jreVer =~ "^(1\.7)")
{
  jreVer = ereg_replace(pattern:"_|-", string:jreVer, replace: ".");

  ##Check for Oracle Java SE Versions
  if(version_in_range(version:jreVer, test_version:"1.7.0.0", test_version2:"1.7.0.25"))
  {
    security_hole(0);
    exit(0);
  }
}
