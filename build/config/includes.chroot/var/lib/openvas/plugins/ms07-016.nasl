###################################################################
# OpenVAS Vulnerability Test
#
# Cumulative Security Update for Internet Explorer (928090)
#
# LSS-NVT-2010-043
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2010 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

include("revisions-lib.inc");
tag_solution = "Microsoft has released an update to correct this issue,
  you can download it from the following web site:
  http://www.microsoft.com/technet/security/bulletin/ms07-016.mspx";
tag_summary = "Microsoft Internet Explorer is affected by multiple critical vulnerabilities.
  These vulnerabilities could allow remote code execution each via a different
  attack vector.";

if(description)
{
  script_id(102054);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-08 10:59:30 +0200 (Thu, 08 Jul 2010)");
  script_cve_id("CVE-2006-4697", "CVE-2007-0217", "CVE-2007-0219");
  script_bugtraq_id(22486, 22489, 22504);
  script_name("Cumulative Security Update for Internet Explorer (928090)");
  desc = "
  Summary:
  " + tag_summary + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4697");
  script_xref(name : "URL" , value : "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0217");
  script_xref(name : "URL" , value : "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0219");
  script_description(desc);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_summary("Checks for Internet Explorer version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/EXE/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3) <= 0) {
  exit(0);
}

version = get_kb_item("MS/IE/EXE/Ver");
if (!version) {
  exit (0);
}

# MS07-016 Hotfix (928090)
if(hotfix_missing(name:"928090") == 0) {
  exit(0);
}

dllPath = registry_get_sz(item:"Install Path",
                          key:"SOFTWARE\Microsoft\COM3\Setup");
dllPath += "\mshtml.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

vers = GetVer(file:file, share:share);
if(!vers) {
  exit(0);
}


# First checking Win2K SP4

if (hotfix_check_sp(win2k:5) > 0) {
   SP = get_kb_item("SMB/Win2K/ServicePack");
   if("Service Pack 4" >< SP) {
    # Must have IE 5.01 SP4 or IE 6 (any) 
    is_vuln1 = version_is_equal(version:version, test_version: "5.00.3700.1000");
    is_vuln2 = version_in_range(version:version, test_version:"6.00.2462.0000", test_version2:"6.00.3790.3959");
    if (is_vuln1) {
       # Grep for mshtml.dll version < 5.0.3849.500
       if(version_in_range(version:vers, test_version:"5.0", test_version2:"5.0.3849.499")) {
          security_hole(0);
       }
       exit (0);
    }
    else if (is_vuln2) {
       # Grep for mshtml.dll version < 6.0.2800.1589
       if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2800.1588")) {
          security_hole(0);
       }
       exit (0);
    }
   }
}
# WinXP SP2
else if (hotfix_check_sp(xp:4) > 0) {
   SP = get_kb_item("SMB/WinXP/ServicePack");
   if("Service Pack 2" >< SP) {
    # Must have IE 6 (any) or IE 7 (any) 
    is_vuln1 = version_in_range(version:version, test_version:"6.00.2462.0000", test_version2:"6.00.3790.3959");
    is_vuln2 = version_in_range(version:version, test_version:"7.00.5730.1100", test_version2:"7.00.6001.1800");
    if (is_vuln1) {
       # Grep for mshtml.dll version < 6.0.2900.3059
       if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2900.3058")) {
          security_hole(0);
       }
       exit (0);
    }
    else if (is_vuln2) {
       # Grep for mshtml.dll version < 7.0.6000.16414
       if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.6000.16413")) {
          security_hole(0);
       }
       exit (0);
    }
   }
}
else if (hotfix_check_sp(win2003:3) > 0) {
    # Must have IE 6 or IE 7
    is_vuln1 = version_is_equal(version:version, test_version:"7.00.6000.16441");
    is_vuln2 = version_in_range(version:version, test_version:"6.00.3663.0000", test_version2:"6.00.3718.0000");
    if (is_vuln1) {
       # Grep for mshtml.dll version < 7.0.6000.16414
       if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.6000.16413")) {
          security_hole(0);
       }
       exit (0);
    }
    else if (is_vuln2) {
       # Grep for mshtml.dll version < 6.0.3790.630
       if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.3790.629")) {
          security_hole(0);
       }
       exit (0);
    }
}

