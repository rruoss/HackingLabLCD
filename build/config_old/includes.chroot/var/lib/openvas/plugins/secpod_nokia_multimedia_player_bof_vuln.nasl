###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_nokia_multimedia_player_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Nokia Multimedia Player Playlist Processing Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to crash an affected
  application or compromise a vulnerable system by tricking a user into opening
  a malicious playlist file.
  Impact Level: Application.";
tag_affected = "Nokia Multimedia Player Version 1.00.55.5010 and prior";

tag_insight = "The flaw is caused by a buffer overflow error when processing playlists
  containing overly long data.";
tag_solution = "No solution or patch is available as of 28th January, 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.nokia.com/";
tag_summary = "This host is installed with Nokia Multimedia Player and is prone
  to buffer overflow vulnerability.";

if(description)
{
  script_id(902331);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2011-0498");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Nokia Multimedia Player Playlist Processing Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/70416");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42852");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0083");

  script_description(desc);
  script_summary("Check for the version of Nokia Multimedia Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
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
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Nokia\Nokia Multimedia Player")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  nmpName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Check the name of the application
  if("Nokia Multimedia Player" >< nmpName)
  {
    nmpPath = registry_get_sz(key:key + item, item:"InstallLocation");

    if(!isnull(nmpPath))
    {
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:nmpPath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:nmpPath +
                                                            "\NokiaMMSViewer.exe");
      ## Get the version
      nmpVer = GetVer(file:file, share:share);
      if(nmpVer != NULL)
      {
        ## Check for Nokia Multimedia Player version < 1.00.55.5010(1.0.0.55)
        if(version_is_less_equal(version:nmpVer, test_version:"1.0.0.55"))
        {
          security_hole(0);
          exit(0);
        }
      }
    }
  }
}
