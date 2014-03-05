###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_win_kernel_win32k_sys_priv_esc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft Windows Kernel 'win32k.sys' Privilege Escalation Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow local administrators to bypass unspecified
  'security software' and gain privileges.
  Impact Level: System";
tag_affected = "Microsoft Windows XP SP2/SP3 and prior
  Microsoft Windows Server 2003 before SP1.";
tag_insight = "The flaw is due to error in NtUserConsoleControl function in win32k.sys
  caused via a crafted call that triggers an overwrite of an arbitrary memory
  location.";
tag_solution = "No solution or patch is available as of 07th August, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/en/us/default.aspx";
tag_summary = "Windows XP/2003 is prone to Privilege Escalation vulnerability.";

if(description)
{
  script_id(800862);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-11 07:36:16 +0200 (Tue, 11 Aug 2009)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2653");
  script_name("Microsoft Windows Kernel win32k.sys Privilege Escalation Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9301");
  script_xref(name : "URL" , value : "http://www.ntinternals.org/index.html#09_07_30");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Jul/1022630.html");

  script_description(desc);
  script_summary("Check for the Windows win32k.sys Existence");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Privilege escalation");
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

winVer = get_kb_item("SMB/WindowsVersion");

# Check for Windows XP and Windows 2003
if(winVer =~ "^5\.[12]")
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  SvPk = get_kb_item("SMB/Win2003/ServicePack");
  # Check for XP SP2/SP3 or Win 2003 (without SP)
  if(("Service Pack 2" >< SP) || ("Service Pack 3" >< SP) || isnull(SvPk))
  {
    sysPath = registry_get_sz(item:"Install Path",
                              key:"SOFTWARE\Microsoft\COM3\Setup");
    sysPath += "\win32k.sys";
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath);
    sysVer = GetVer(file:file, share:share);

    # Chech for win32k.sys version for Windows XP
    if(sysVer =~ "^5\.1\..*")
    {
      # Check for win32k.sys version <= 5.1.2600.5796 for Windows XP SP2/SP3
      if(version_is_less_equal(version:sysVer, test_version:"5.1.2600.5796"))
        security_warning(0);
    }
    # Check for win32k.sys version for Windows 2003
    else if(sysVer =~ "^5\.2\..*")
      security_warning(0);
 }
}
