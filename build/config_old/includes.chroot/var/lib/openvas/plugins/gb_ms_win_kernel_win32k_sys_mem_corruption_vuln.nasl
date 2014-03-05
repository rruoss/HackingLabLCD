###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_win_kernel_win32k_sys_mem_corruption_vuln.nasl 18 2013-10-27 14:14:13Z jan $
#
# Microsoft Windows Kernel 'win32k.sys' Memory Corruption Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code on
  the system with kernel-level privileges.
  Impact Level: System";
tag_affected = "Microsoft Windows 7 Professional 64-bit";
tag_insight = "The flaw is due to an error in win32k.sys, when handling a specially
  crafted web page containing an IFRAME with an overly large 'height'
  attribute viewed using the Apple Safari browser.";
tag_solution = "No solution or patch is available as of 13th January, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/en/us/default.aspx";
tag_summary = "Microsoft Windows 7 Professional 64-bit is prone to memory
  corruption vulnerability.";

if(description)
{
  script_id(802379);
  script_version("$Revision: 18 $");
  script_cve_id("CVE-2011-5046");
  script_bugtraq_id(51122);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft Windows Kernel 'win32k.sys' Memory Corruption Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/77908");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47237");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71873");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18275/");

  script_description(desc);
  script_summary("Check for the Windows win32k.sys Existence");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
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
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win7:2) <= 0){
  exit(0);
}

#Get the system architecture
key = "SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
if(!registry_key_exists(key:key)){
  exit(0);
}

#Check if its 64-bit system
sysArch = registry_get_sz(key:key, item:"PROCESSOR_ARCHITECTURE");
if("AMD64" >< sysArch)
{
  ## Get System Path
  sysPath = smb_get_systemroot();
  if(!sysPath ){
    exit(0);
  }

  ## Get Version from Win32k.sys
  sysVer = fetch_file_version(sysPath, file_name:"system32\Win32k.sys");

  if(!isnull(sysVer))
  {
    if(version_is_less_equal(version:sysVer, test_version:"6.1.7601.17730"))
    {
      security_hole(0);
      exit(0);
    }
  }
}
