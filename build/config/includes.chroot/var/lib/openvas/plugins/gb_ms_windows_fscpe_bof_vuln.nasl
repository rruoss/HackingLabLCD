###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_windows_fscpe_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft Windows Fax Cover Page Editor BOF Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow the attacker to cause a heap-based buffer
  overflow via a Fax Cover Page file containing specially crafted content.
  Impact Level: System/Application";
tag_affected = "Fax Services Cover Page Editor 5.2 r2 on,
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.
  Micorsoft Windows 7";
tag_insight = "The flaw is due to an input validation error and a use-after-free
  error in the Fax Cover Page Editor 'fxscover.exe' when a function
  'CDrawPoly::Serialize()' reads in data from a Fax Cover Page file ('.cov').";
tag_solution = "No solution or patch is available as of 24th january, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/";
tag_summary = "This host is installed with Fax Cover Page Editor and is prone to
  buffer overflow vulnerabilities.";

if(description)
{
  script_id(801580);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)");
  script_cve_id("CVE-2010-4701");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Microsoft Windows Fax Cover Page Editor BOF Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42747");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1024925");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15839/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16024/");

  script_description(desc);
  script_summary("Check for the version of fxscover.exe file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Windows");
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

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, win2003:3, win7:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllPath = sysPath + "\system32\fxscover.exe";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

## Get Version from fxscover.exe file
dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

## Check for fxscover.exe version
if(version_is_less_equal(version:dllVer, test_version:"5.2.3790.3959")){
  security_hole(0);
}
