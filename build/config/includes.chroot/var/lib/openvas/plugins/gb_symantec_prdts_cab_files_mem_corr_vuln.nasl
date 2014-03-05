###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_prdts_cab_files_mem_corr_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Symantec Products CAB Files Memory Corruption Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Upgrade to Symantec Endpoint Protection (SEP) version 12.1 or later
  For updates refer to http://www.symantec.com/business/support/index?page=content&id=TECH163602

  *****
  NOTE: Ignore this warning if patch or mentioned workaround is applied already.
        For patch or workaround refer to
        http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20121107_00
  *****";

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code or can cause a denial of service via a crafted CAB file.
  Impact Level: System/Application";
tag_affected = "Symantec Endpoint Protection (SEP) version 11.x
  Symantec Endpoint Protection Small Business Edition version 12.0.x
  Symantec AntiVirus Corporate Edition (SAVCE) version 10.x";
tag_insight = "The decomposer engine in Symantec Products fails to perform bounds checking
  when parsing files from CAB archives.";
tag_summary = "This host is installed with Symantec Product and is prone to
  memory corruption vulnerability.";

if(description)
{
  script_id(803054);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4953");
  script_bugtraq_id(56399);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-22 12:16:15 +0530 (Thu, 22 Nov 2012)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Symantec Products CAB Files Memory Corruption Vulnerability");
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


  script_description(desc);
  script_summary("Check for the version of vulnerable Symantec Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_require_keys("Symantec/Endpoint/Protection", "Symantec/SEP/SmallBusiness",
                      "Symantec/SAVCE/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_xref(name : "URL" , value : "http://www.osvdb.org/87403");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49248/");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/985625");
  script_xref(name : "URL" , value : "http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;year=&amp;suid=20121107_00");
  exit(0);
}


include("version_func.inc");

## Variable Initialisation
sepVer = "";
sepType = "";
savceVer = "";

## Get Symantec AntiVirus Corporate Edition version from KB
## Check for SAVCE version 10.x
savceVer = get_kb_item("Symantec/SAVCE/Ver");
if(savceVer && savceVer =~ "^10")
{
   security_hole(0);
   exit(0);
}

## Get Symantec Endpoint Protection version
sepVer = get_kb_item("Symantec/Endpoint/Protection");
if(!sepVer){
 exit(0);
}

## Get SEP Product type from KB
sepType = get_kb_item("Symantec/SEP/SmallBusiness");

## Check for Symantec Endpoint Protection version 11.x
if(isnull(sepType) && sepVer =~ "^11")
{
   security_hole(0);
   exit(0);
}

## Check for Symantec Endpoint Protection Small Business Edition (SEPSBE) 12.0.x
## Check if product type is SEPSB
if("sepsb" >< sepType  && sepVer =~ "^12.0")
{
   security_hole(0);
   exit(0);
}
