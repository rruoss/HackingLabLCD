###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_kingsoft_antivirus_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Kingsoft Antivirus 'KisKrnl.sys' Driver Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow local users to cause a denial of service
  condition.
  Impact Level: Application.";
tag_affected = "Kingsoft Antivirus version 2011.1.13.89 and prior.";

tag_insight = "The flaw is due to an error when handling system service calls in the
  'kisknl.sys' driver which can be exploited to cause a page fault error in
  the kernel and crash the system.";
tag_solution = "No solution or patch is available as of 28th January, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.kingsoftsecurity.com/kingsoft-antivirus.html";
tag_summary = "This host is installed with Kingsoft Antivirus and is prone to
  denial of service vulnerability.";

if(description)
{
  script_id(901176);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2011-0515");
  script_bugtraq_id(45821);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Kingsoft Antivirus 'KisKrnl.sys' Driver Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42937");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64723");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15998/");

  script_description(desc);
  script_summary("Check for the version of Kingsoft Antivirus");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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

if(!registry_key_exists(key:"SOFTWARE\Kingsoft")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" +
                   "Kingsoft Internet Security";

if(!registry_key_exists(key:key)){
  exit(0);
}

## Check for Kingsoft Antivirus DisplayName
ksantName = registry_get_sz(key:key, item:"DisplayName");

if("Kingsoft AntiVirus" >< ksantName)
{
  ## Check for Kingsoft Antivirus DisplayIcon
  ksantPath = registry_get_sz(key:key + item, item:"DisplayIcon");
  if(!isnull(ksantPath))
  {
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ksantPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:ksantPath);

    ## Check for Kingsoft Antivirus .exe File Version
    ksantVer = GetVer(file:file, share:share);
    if(ksantVer != NULL)
    {
      ## Check for Kingsoft Antivirus version <= 2011.1.13.89
      if(version_is_less_equal(version:ksantVer, test_version:"2011.1.13.89")){
        security_warning(0) ;
      }
    }
  }
}
