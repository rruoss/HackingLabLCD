###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ultra_edit_insecure_library_loading_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# UltraEdit Insecure Library Loading Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.org
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code.
  Impact Level: Application.";
tag_affected = "UltraEdit version 16.20.0.1009 and prior.";

tag_insight = "The flaw exists due to the application loading libraries in an insecure manner.
  This can be exploited to load arbitrary libraries by tricking a user into
  opening a UENC file located on a remote WebDAV or SMB share.";
tag_solution = "No solution or patch is available as of 20th September, 2010. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.ultraedit.com/";
tag_summary = "This host is installed with UltraEdit and is prone
  to insecure library loading vulnerability.";

if(description)
{
  script_id(902307);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_cve_id("CVE-2010-3402");
  script_bugtraq_id(43183);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("UltraEdit Insecure Library Loading Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/67995");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41403");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2010-09/0227.html");

  script_description(desc);
  script_summary("Check for the version of UltraEdit");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ueName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Check the name of the application
  if("UltraEdit" >< ueName)
  {
    ## Check for UltraEdit Installed location
    uePath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!isnull(uePath))
    {
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:uePath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:uePath + "\Uedit32.exe");

      ## Check for UltraEdit File Version
      ueVer = GetVer(file:file, share:share);
      if(ueVer != NULL)
      {
        ## Check for UltraEdit version <= 16.20.0.1009
        if(version_is_less_equal(version:ueVer, test_version:"16.20.0.1009")){
          security_hole(0) ;
        }
      }
    }
  }
}
