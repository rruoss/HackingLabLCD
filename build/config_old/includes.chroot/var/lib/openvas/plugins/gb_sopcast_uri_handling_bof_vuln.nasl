###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sopcast_uri_handling_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# SopCast 'sop://' URI Handling Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  code in the context of the user running an affected application. Failed
  exploit attempts may lead to a denial-of-service condition.
  Impact Level: System/Application";
tag_affected = "SopCast version 3.4.7.45585";
tag_insight = "The flaw is due to a boundary error in the WebPlayer ActiveX Control
  when handling the 'ChannelName' property can be exploited to cause a stack
  based buffer overflow via a specially crafted 'sop://' URL string.";
tag_solution = "No solution or patch is available as of 8th December, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.sopcast.com/";
tag_summary = "This host is installed with SopCast and is prone to buffer overflow
  vulnerability.";

if(description)
{
  script_id(802281);
  script_version("$Revision: 13 $");
  script_bugtraq_id(50901);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-08 15:15:15 +0530 (Thu, 08 Dec 2011)");
  script_name("SopCast 'sop://' URI Handling Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40940");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18200");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/107528/ZSL-2011-5063.txt");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5063.php");

  script_description(desc);
  script_summary("Check for the version of SopCast");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
include("version_func.inc");
include("secpod_smb_func.inc");

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm SopCast
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SopCast";
if(!registry_key_exists(key:key)){
  exit(0);
}

sopName = registry_get_sz(key:key, item:"DisplayName");
if("SopCast" >< sopName)
{
  ## Get Installation Path
  sopPath = registry_get_sz(key:key, item:"DisplayIcon");
  if(!sopPath){
    exit(0);
  }
  sopPath = sopPath - "\SopCast.exe";

  ## Get Version from sopocx.ocx
  sopVer = fetch_file_version(sysPath:sopPath, file_name:"sopocx.ocx");
  if(! sopVer){
   exit(0);
  }

  ## Check for SopCast version 3.4.7.45585
  if(version_is_equal(version:sopVer, test_version:"3.4.7.45585")) {
    security_hole(0);
  }
}
