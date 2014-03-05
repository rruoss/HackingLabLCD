###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ultra_player_buf_overflow_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# UltraPlayer Media Player Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code within the context of the affected application.
  Impact Level: System/Application";
tag_affected = "UltraPlayer Media Player 2.112";
tag_insight = "The flaw is caused by improper bounds checking when parsing malicious
  '.usk' files. By tricking a victim to open a specially crafted .usk file,
  an attacker could exploit this vulnerability.";
tag_solution = "No solution or patch is available as of 17th May, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.ultraplayer.com/index.asp";
tag_summary = "This host is installed with UltraPlayer Media Player and is
  prone to buffer overflow vulnerability.";

if(description)
{
  script_id(801207);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_bugtraq_id(35956);
  script_cve_id("CVE-2009-4863");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("UltraPlayer Media Player Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/52281");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2160");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9368");

  script_description(desc);
  script_summary("Check for the version of UltraPlayer Media Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
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
include("secpod_smb_func.inc");
include("version_func.inc");

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Get Application Installed Path
upPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                     "\App Paths\UPlayer.exe", item:"Path");
if(!upPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$", string:upPath);
file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1",
                                        string:upPath + "\UPlayer.exe");

## Get UltraPlayer Media Player Version
upVer = GetVer(share:share, file:file);

if(upVer)
{
  ## Grep for UltraPlayer Media Player version = 2.1.1.2
  if(version_is_equal(version: upVer, test_version: "2.1.1.2")){
    security_hole(0);
  }
}
