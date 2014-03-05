###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_realtek_media_player_bof_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# Realtek Media Player Playlist Buffer Overflow Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright (c) 2008 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code to cause buffer overflow and can lead to application crash.
  Impact Level: Application";
tag_affected = "Realtek Media Player A4.06 (5.36) and prior on Windows.";
tag_insight = "The issue is due to improper bounds checking when processing
  playlist files.";
tag_solution = "No solution or patch is available as of 26th December, 2008. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.realtek.com.tw/downloads/";
tag_summary = "This host has Realtek Media Player installed and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_id(900067);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-29 13:55:43 +0100 (Mon, 29 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-5664");
  script_bugtraq_id(32860);
  script_name("Realtek Media Player Playlist Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7492");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/47380");

  script_description(desc);
  script_summary("Check for the version of Realtek Media Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Denial of Service");
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

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Realtek Semiconductor Corp.")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  if("Realtek" >< registry_get_sz(key:key + item, item:"DisplayName"))
  {
    rmpVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(!rmpVer){
      exit(0);
    }

    # Realtek Version <= 5.36 (A4.06)
    if(version_is_less_equal(version:rmpVer, test_version:"5.36")){
      security_hole(0);
    }
    exit(0);
  }
}
