###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_amr_dos_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# VLC Media Player '.amr' File Denial of Service Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation could allow attackers to crash the affected
  application, denying service to legitimate users.
  Impact Level: Application";
tag_affected = "VLC media player version prior to 1.1.11 on Windows.";
tag_insight = "The flaw is due to an access violation error, when opening a specially-crafted
  '.amr' file, which allows remote attacker to cause the application to crash.";
tag_solution = "No solution or patch is available as of 23rd January, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer http://www.videolan.org/vlc/";
tag_summary = "The host is installed with VLC Media Player and is prone to denial
  of service vulnerability.";

if(description)
{
  script_id(802420);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0904");
  script_bugtraq_id(51255);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-23 15:30:49 +0530 (Mon, 23 Jan 2012)");
  script_name("VLC Media Player '.amr' File Denial of Service Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72085");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18309/");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2012-01/0033.html");

  script_description(desc);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_summary("Check for the version of VLC Media Player");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_require_keys("VLCPlayer/Win/Ver");
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

## Get the version from KB
vlcVer = get_kb_item("VLCPlayer/Win/Ver");
if(!vlcVer){
  exit(0);
}

## Check for VLC Media Player Version less than 1.1.11
if(version_is_equal(version:vlcVer, test_version:"1.1.11")){
  security_warning(0);
}
