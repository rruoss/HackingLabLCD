###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_indesign_insecure_lib_load_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe InDesign Insecure Library Loading Vulnerability (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow the attackers to execute arbitrary code and
  conduct DLL hijacking attacks.
  Impact Level: Application.";
tag_affected = "Adobe InDesign version CS4 6.0";

tag_insight = "The flaw is due to the application insecurely loading certain librairies
  from the current working directory, which could allow attackers to execute
  arbitrary code by tricking a user into opening a file from a network share.";
tag_solution = "No solution or patch is available as of 08th September, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe InDesign and is prone to insecure
  library loading vulnerability.";

if(description)
{
  script_id(801508);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_cve_id("CVE-2010-3153");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe InDesign Insecure Library Loading Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41126");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14775/");

  script_description(desc);
  script_summary("Check for the version of Adobe InDesign");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_indesign_detect.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("version_func.inc");

## Check for Adobe InDesign
adVer = get_kb_item("Adobe/InDesign/Ver");
if(isnull(adVer)){
  exit(0);
}

adobeVer = eregmatch(pattern:" ([0-9.]+)", string:adVer);
if(!isnull(adobeVer[1]) && ("CS4" >< adVer))
{
  ## Check for Adobe InDesign CS4 version equals to 6.0
  if(version_is_equal(version:adobeVer[1], test_version:"6.0")){
    security_hole(0);
  }
}
