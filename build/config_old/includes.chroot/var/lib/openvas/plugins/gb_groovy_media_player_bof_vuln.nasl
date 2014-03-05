###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_groovy_media_player_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Groovy Media Player '.m3u' File Remote Stack Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allows remote attackers to cause a denial of
  service or possibly execute arbitrary code.
  Impact Level: Application.";
tag_affected = "Groovy Media Player 1.1.0";

tag_insight = "The flaw is caused by improper bounds checking when parsing malicious '.M3U'
  files.";
tag_solution = "No solution or patch is available as of 13th July, 2010. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.bestwebsharing.com/groovy-media-player";
tag_summary = "This host is installed with Groovy Media Player and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_id(801405);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-16 19:44:55 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2009-4931");
  script_bugtraq_id(34621);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Groovy Media Player '.m3u' File Remote Stack Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/395659.php");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49965");

  script_description(desc);
  script_summary("Check for the version of Groovy Media Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Groovy Media Player")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
            "\Groovy Media Player";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Check for Groovy Media Player DisplayName
gmpName = registry_get_sz(key:key, item:"DisplayName");

if("Groovy Media Player" >< gmpName)
{
  ## Get the version from registry key
  gmpVer = registry_get_sz(key:key, item:"DisplayVersion");
  if(gmpVer != NULL)
  {
    ## Check for the Groovy Media Player version equal to '1.1.0'
    if(version_is_equal(version:gmpVer, test_version:"1.1.0")){
        security_hole(0);
    }
  }
}
