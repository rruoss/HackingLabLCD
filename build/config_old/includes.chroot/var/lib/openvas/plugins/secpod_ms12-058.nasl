###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-058.nasl 12 2013-10-27 11:15:33Z jan $
#
# MS Exchange Server WebReady Document Viewing Remote Code Execution Vulnerabilities (2740358)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow an attacker to run arbitrary code as
  LocalService on the affected Exchange server.
  Impact Level: Application";
tag_affected = "Microsoft Exchange Server 2007 Service Pack 3
  Microsoft Exchange Server 2010 Service Pack 1
  Microsoft Exchange Server 2010 Service Pack 2";
tag_insight = "The flaws are caused when WebReady Document Viewer is used to preview a
  specially crafted file.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS12-058.";

if(description)
{
  script_id(903038);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1766", "CVE-2012-1767", "CVE-2012-1768", "CVE-2012-1769",
                "CVE-2012-1770", "CVE-2012-1771", "CVE-2012-1772", "CVE-2012-1773",
                "CVE-2012-3106", "CVE-2012-3107", "CVE-2012-3108", "CVE-2012-3109",
                "CVE-2012-3110.");
  script_bugtraq_id(54531, 54511, 54536, 54500, 54541, 54543, 54497, 54548,
                    54546, 54504, 54550, 54554, 54506);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-15 15:41:59 +0530 (Wed, 15 Aug 2012)");
  script_name("MS Exchange Server WebReady Document Viewing Remote Code Execution Vulnerabilities (2740358)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50019/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2740358");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/advisory/2737111");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-058");

  script_description(desc);
  script_summary("Check for the version of 'TranscodingService.exe' file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
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
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


## Variables Initialization
key = "";
version = "";
exeVer = "";
exchangePath = "";


## Confirm the application
if(!registry_key_exists(key:"SOFTWARE\Microsoft\Exchange")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach version (make_list("Microsoft Exchange v14", "Microsoft Exchange"))
{
  key = key + version;
  exchangePath = registry_get_sz(key:key, item:"InstallLocation");

  if(exchangePath)
  {
    ## Get Version from TranscodingService.exe file version
    exeVer = fetch_file_version(sysPath:exchangePath,
             file_name:"ClientAccess\Owa\Bin\DocumentViewing\TranscodingService.exe");
    if(exeVer)
    {
      ## Check for TranscodingService.exe version
      if(version_is_less(version:exeVer, test_version:"8.3.279.4") ||
         version_in_range(version:exeVer, test_version:"14.1", test_version2:"14.1.421.1") ||
         version_in_range(version:exeVer, test_version:"14.2", test_version2:"14.2.318.3"))
      {
        security_warning(0);
        exit(0);
      }
    }
  }
}
