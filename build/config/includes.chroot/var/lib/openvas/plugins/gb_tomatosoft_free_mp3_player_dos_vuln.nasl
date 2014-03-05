###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tomatosoft_free_mp3_player_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# TomatoSoft Free Mp3 Player '.mp3' File Denial of Service Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to cause the application
  to crash.
  Impact Level: Application";
tag_affected = "TomatoSoft Free Mp3 Player 1.0";
tag_insight = "The flaw is due to an error when parsing a crafted '.mp3' file
  containing an overly long argument.";
tag_solution = "No solution or patch is available as of 6th January, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.tomatosoft.biz/blog/2011/12/09/free-mp3-player/";
tag_summary = "This host is installed with TomatoSoft Free Mp3 Player and is
  prone to denial of service vulnerability.";

if(description)
{
  script_id(802370);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-5043");
  script_bugtraq_id(51123);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-05 12:20:03 +0530 (Thu, 05 Jan 2012)");
  script_name("TomatoSoft Free Mp3 Player '.mp3' File Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71870");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18254/");

  script_description(desc);
  script_summary("Check for the version of TomatoSoft Free Mp3 Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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

## Get Related Registry key
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Mp3Player";
if(!registry_key_exists(key:key)){
  exit(0);
}

playerName = registry_get_sz(key:key , item:"Publisher");

## Confirm application
if("Tomatosoft" >< playerName)
{
  playerVer = registry_get_sz(key:key , item:"DisplayName");
  playerVer = eregmatch(pattern:"Mp3 Player ([0-9.]+)", string:playerVer);

  if(playerVer != NULL)
  {
    ## Check for TomatoSoft Free Mp3 Player < 1.0 version
    if(version_is_less_equal(version:playerVer[1], test_version:"1.0"))
    {
      security_warning(0);
      exit(0);
    }
  }
}
