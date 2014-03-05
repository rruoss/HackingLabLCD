###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_win_color_control_panel_priv_escalation.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft Windows Color Control Panel Privilege Escalation Vulnerability
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
tag_impact = "Successful attempt could allow local attackers to bypass security restrictions
  and gain the privileges.
  Impact Level: System";
tag_affected = "Microsoft Windows Server 2008 SP2";
tag_insight = "The flaw is due to an error in the Color Control Panel, which allows
  attackers to gain privileges via a Trojan horse sti.dll file in the current
  working directory.";
tag_solution = "No solution or patch is available as of 19th January, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/en/us/default.aspx";
tag_summary = "Microsoft Windows Server 2008 SP2 is prone to privilege escalation
  vulnerability.";

if(description)
{
  script_id(802383);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2010-5082");
  script_bugtraq_id(44157);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-19 16:17:52 +0530 (Thu, 19 Jan 2012)");
  script_name("Microsoft Windows Color Control Panel Privilege Escalation Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.koszyk.org/b/archives/82");
  script_xref(name : "URL" , value : "http://shinnai.altervista.org/exploits/SH-006-20100914.html");
  script_xref(name : "URL" , value : "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-5082");

  script_description(desc);
  script_summary("Check for the Windows colorcpl.exe Existence");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
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

if(hotfix_check_sp(win2008:3) <= 0){
  exit(0);
}

SP = get_kb_item("SMB/Win2008/ServicePack");
if("Service Pack 2" >< SP)
{
  ## Get System Path
  sysPath = smb_get_systemroot();
  if(!sysPath ){
    exit(0);
  }

  ## Get Version from Win32k.sys
  sysVer = fetch_file_version(sysPath, file_name:"system32\colorcpl.exe");
  if(!isnull(sysVer))
  {
    if(version_is_equal(version:sysVer, test_version:"6.0.6000.16386"))
    {
      security_hole(0);
      exit(0);
    }
  }
}
