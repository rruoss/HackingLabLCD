###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cowon_jetaudio_title_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# jetAudio jetCast Title Processing Buffer Overflow Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  and cause a stack-based buffer overflow by tricking the user into opening an
  MP3 or FLAC file containing an overly long title.
  Impact Level: Application";
tag_affected = "COWON Media Center JetAudio 7.5.2 through 7.5.3.15 on Windows";
tag_insight = "The flaw is due to a boundary error in the jetCast component when processing
  song titles.";
tag_solution = "No solution or patch is available as of 10th March, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.jetaudio.com/";
tag_summary = "This host has COWON Media Center JetAudio installed and is prone
  to Buffer Overflow vulnerability.";

if(description)
{
  script_id(800994);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-4668", "CVE-2009-4676");
  script_name("jetAudio jetCast Title Processing Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35195");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8780");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/503826/100/0/threaded");

  script_description(desc);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_summary("Check through the version of 'JetCast.exe' of JetAudio");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_cowon_jetaudio_detect.nasl");
  script_require_keys("JetAudio/Ver");
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

jaVer = get_kb_item("JetAudio/Ver");
if(jaVer != NULL)
{
  if(version_in_range(version:jaVer, test_version:"7.5.2", test_version2:"7.5.3.15"))
  {
    exePath = registry_get_sz(key:"SOFTWARE\COWON\Jet-Audio", item:"InstallPath_Main");
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
    file = ereg_replace(pattern:"[A-Z]:(.*)",  replace:"\1",  string:exePath +
                                                              "\JetCast.exe");
    exeVer = GetVer(file:file, share:share);
    if(exeVer != NULL)
    {
      # Check if the version is equal to 2.0.4.1109
      if(version_is_less_equal(version:exeVer, test_version:"2.0.4.1109")){
        security_hole(0);
      }
    }
  }
}
