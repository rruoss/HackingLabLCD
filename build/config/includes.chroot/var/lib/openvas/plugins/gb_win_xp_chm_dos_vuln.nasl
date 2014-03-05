###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_win_xp_chm_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft Windows XP SP3 denial of service vulnerability.
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2011-09-22
#  Updated the version check for itss.dll
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
tag_impact = "Successful remote exploitation could result in administrator access,
  unauthorized disclosure of information and disruption of service by
  executing arbitrary code.
  Impact Level: System";
tag_affected = "Microsoft Windows XP SP3 and prior.";
tag_insight = "The flaw is due to an error generated in Windows XP while handling CHM
  files causing buffer overflow.";
tag_solution = "No solution or patch is available as of 22th September, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.securityfocus.com/bid/33204/solution";
tag_summary = "The host is running Microsoft Windows XP which is prone to
  denial of service vulnerability.";

if(description)
{
  script_id(800504);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-19 13:47:40 +0100 (Mon, 19 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0119");
  script_bugtraq_id(33204);
  script_name("Microsoft Windows XP SP3 denial of service vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7720");
  script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?execution=e3s1");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2009-0119");

  script_description(desc);
  script_summary("Check for the version of Microsoft Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Confirm the windows platform
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm the windows XP
if(hotfix_check_sp(xp:4) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from itss.dll
dllVer = fetch_file_version(sysPath, file_name:"system32\itss.dll");
if(!dllVer){
  exit(0);
}

if(version_is_less_equal(version:dllVer, test_version:"5.2.3790.4186")){
  security_hole(0);
}
