###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_kingsoft_antivirus_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Kingsoft Antivirus 'kavfm.sys' Buffer overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  with SYSTEM-level privileges and completely compromise the affected computer.
  Failed exploit attempts will result in a denial-of-service condition.
  Impact Level: Application.";
tag_affected = "Kingsoft Antivirus 2010.04.26.648 and prior";

tag_insight = "The flaw exists due to an error in the 'kavfm.sys' driver when processing
  'IOCTLs'. This can be exploited to corrupt kernel memory and potentially
  execute arbitrary code with escalated privileges via a specially crafted
  0x80030004 IOCTL.";
tag_solution = "No solution or patch is available as of 16th September, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.kingsoftsecurity.com/kingsoft-antivirus.html";
tag_summary = "This host is installed with Kingsoft Antivirus and is prone
  to buffer overflow vulnerability.";

if(description)
{
  script_id(902302);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_cve_id("CVE-2010-3396");
  script_bugtraq_id(43173);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Kingsoft Antivirus 'kavfm.sys' Buffer overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41393");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14987/");

  script_description(desc);
  script_summary("Check for the version of Kingsoft Antivirus");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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
      ## Check for Kingsoft Antivirus version <= 2010.04.26.648
      if(version_is_less_equal(version:ksantVer, test_version:"2010.04.26.648")){
        security_hole(0) ;
      }
    }
  }
}
