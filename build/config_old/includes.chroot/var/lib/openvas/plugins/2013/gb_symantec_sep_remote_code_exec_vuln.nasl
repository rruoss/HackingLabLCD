###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_sep_remote_code_exec_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Symantec Endpoint Protection Management Console Remote Code Execution Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation could allow remote authenticated users to execute
  arbitrary code via unspecified vectors.
  Impact Level: System/Application";

tag_affected = "Symantec Endpoint Protection (SEP) versions 11.0 before RU7-MP3 and 12.1 before RU2
  Symantec Endpoint Protection Small Business Edition version 12.x before 12.1 RU2";
tag_insight = "The decomposer engine in Symantec Products fails to properly validate input
  for PHP scripts.";
tag_solution = "Upgrade to Symantec Endpoint Protection (SEP) version 11.0 RU7-MP3 or SEP12.1 RU2 or later
  http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20121210_00";
tag_summary = "This host is installed with Symantec Endpoint Protection and is
  prone to remote code execution vulnerability.";

if(description)
{
  script_id(803094);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-4348");
  script_bugtraq_id(56846);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-08 10:42:29 +0530 (Tue, 08 Jan 2013)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Symantec Endpoint Protection Management Console Remote Code Execution Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://www.osvdb.org/88347");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51527");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/80601");
  script_xref(name : "URL" , value : "http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;year=&amp;suid=20121210_00");

  script_description(desc);
  script_summary("Check for the version of vulnerable Symantec Endpoint Protection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_require_keys("Symantec/Endpoint/Protection",
                      "Symantec/SEP/SmallBusiness");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

## Variable Initialisation
sepVer = "";
sepType = "";

## Get Symantec Endpoint Protection version
sepVer = get_kb_item("Symantec/Endpoint/Protection");
if(!sepVer){
 exit(0);
}

## Get SEP Product type from KB
sepType = get_kb_item("Symantec/SEP/SmallBusiness");

## Check for Symantec Endpoint Protection versions
## 11.x before RU7-MP3 (11.0.7300.1294) and 12.1 before RU2 (12.1.2015.2015)
if(isnull(sepType) &&
   version_in_range(version:sepVer, test_version:"11.0", test_version2:"11.0.7300.1293")||
   version_in_range(version:sepVer, test_version:"12.1", test_version2:"12.1.2015.2014"))
{
   security_hole(0);
   exit(0);
}

## Check for Symantec Endpoint Protection Small Business Edition (SEPSBE) 12.x before  RU2 (12.1.2015.2015)
## Check if product type is SEPSB
if("sepsb" >< sepType  && sepVer =~ "^12" &&
   version_is_less(version:sepVer, test_version:"12.1.2015.2015"))
{
   security_hole(0);
   exit(0);
}
