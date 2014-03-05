###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_beatport_player_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Beatport Player '.m3u' File Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code
  on the system or cause the application to crash.
  Impact Level: Application";
tag_affected = "Beatport Player version 1.0.0.283 and prior.";
tag_insight = "The flaw is due to improper bounds ckecking when opening specially
  crafted '.M3U' file.";
tag_solution = "No solution or patch is available as of 6th April, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.beatportplayer.com/";
tag_summary = "This host is installed with Beatport Player and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(800749);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-07 16:20:50 +0200 (Wed, 07 Apr 2010)");
  script_cve_id("CVE-2009-4756");
  script_bugtraq_id(34793);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Beatport Player '.m3u' File Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8592");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50267");

  script_description(desc);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_summary("Check the file version of TraktorBeatport.exe");
  script_category(ACT_GATHER_INFO);
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

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Native Instruments\TraktorBeatport")){
  exit(0);
}

tbpName = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\Uninstall\Native Instruments Traktor Beatport Player",
                         item:"DisplayName");

if("Native Instruments Traktor Beatport Player" >< tbpName)
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                        item:"CommonFilesDir");
  if(isnull(path)){
    exit(0);
  }

  path = path - "\Common Files" + "\Native Instruments\Traktor Beatport Player" +
                                 "\TraktorBeatport.exe";
  share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:path);
  file =  ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:path);

  ver = GetVer(file:file, share:share);
  if(ver != NULL)
  {
    if(version_is_less_equal(version:ver, test_version:"1.0.0.283")){
     security_hole(0);
    }
  }
}
