###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vbsedit_dos_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adersoft VbsEdit '.vbs' File Denial Of Service Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to crash the affected
  application, resulting in a denial-of-service condition.
  Impact Level: Application.";
tag_affected = "Adersoft VbsEdit 4.6.1 and prior";

tag_insight = "The flaw exists due to an error in handling '.vbs' file which allows the
  user to crash the affected application.";
tag_solution = "No solution or patch is available as of 20th August, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.vbsedit.com/";
tag_summary = "This host is installed with VbsEdit and is prone to Denial Of Service
  vulnerability.";

if(description)
{
  script_id(801440);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-25 17:02:03 +0200 (Wed, 25 Aug 2010)");
  script_bugtraq_id(42525);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Adersoft VbsEdit '.vbs' File Denial Of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://inj3ct0r.com/exploits/13733");
  script_xref(name : "URL" , value : "http://www.expbase.com/Dos/12737.html");
  script_xref(name : "URL" , value : "http://www.0daynet.com/2010/0819/995.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/42525/discuss");

  script_description(desc);
  script_summary("Check for the version of VbsEdit");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
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

if(!registry_key_exists(key:"SOFTWARE\Adersoft\Vbsedit")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Vbsedit";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Check the name of the application
vbsName = registry_get_sz(key:key, item:"DisplayName");
if("Vbsedit" >< vbsName)
{
  ## Check for VbsEdit DisplayIcon
  vbsPath = registry_get_sz(key:key, item:"DisplayIcon");

  if(!isnull(vbsPath))
  {
    vbsPath = vbsPath - ",0";
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:vbsPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:vbsPath);

    ## Check for Vbsedit.exe File Version
    vbsVer = GetVer(file:file, share:share);
    if(vbsVer != NULL)
    {
      ## Check for VbsEdit versiom <= 4.6.1
      if(version_is_less_equal(version:vbsVer, test_version:"4.6.1")){
        security_hole(0) ;
      }
    }
  }
}
