###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_windows_sp_mult_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft Windows Service Pack Missing Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_affected = "Microsoft Windows 7
  Microsoft Windows 2K SP3 and prior
  Microsoft Windows XP SP2 and prior
  Microsoft Windows 2K3 SP1 and prior
  Microsoft Windows Vista SP1 and prior
  Microsoft Windows Server 2008 SP1 and prior

  Fix Apply the latest Service Pack,
  For Updated refer, http://www.microsoft.com/";

tag_impact = "Successful exploitation will allow remote attackers to compromise a
  vulnerable system.
  Impact Level: System";
tag_insight = "The flaws are due to a system critical service pack not installed or
  is outdated or obsolete.";
tag_summary = "This host is installed Microsoft Windows and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(902909);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-1999-0662");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-27 12:06:13 +0530 (Tue, 27 Mar 2012)");
  script_name("Microsoft Windows Service Pack Missing Multiple Vulnerabilities");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected;

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/1233");
  script_xref(name : "URL" , value : "http://www.cvedetails.com/cve/CVE-1999-0662/");
  script_xref(name : "URL" , value : "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-0662");

  script_description(desc);
  script_summary("Check for the Microsoft Windows Service Pack version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_keys("SMB/WindowsVersion", "SMB/WindowsName", "SMB/Windows/ServicePack",
                      "SMB/Win2008/ServicePack", "SMB/Win7/ServicePack", "SMB/Win2K/ServicePack",
                      "SMB/WinXP/ServicePack", "SMB/Win2003/ServicePack", "SMB/WinVista/ServicePack");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}

include("version_func.inc");

No_SP = "";
winName = "";
spVer = "" ;
SP = "";
ver = "";

winName = get_kb_item("SMB/WindowsName");
if(!winName){
  exit(0);
}

## Check if service pack is installed or not
No_SP  =  get_kb_item("SMB/Windows/ServicePack");
if(No_SP == "0")
{
  security_hole(0);
  exit(0);
}

## Get the service pack version
function check_sp(SP)
{
  if("Service Pack" >< SP)
  {
    spVer = eregmatch(pattern:"Service Pack ([0-9.]+)", string:SP);
    if(spVer[1]){
       return spVer[1];
    }
    else return 0;
  }
}

## Check service pack version for Windows XP
SP = get_kb_item("SMB/WinXP/ServicePack");
if(SP && (ver = check_sp(SP)))
{
  if(version_is_less(version:ver, test_version:"3"))
  {
    security_hole(0);
    exit(0);
  }
}

## Check service pack version for Windows server 2003
SP = get_kb_item("SMB/Win2003/ServicePack");
if(SP && (ver = check_sp(SP)))
{
  if(version_is_less(version:ver, test_version:"2"))
  {
    security_hole(0);
    exit(0);
  }
}


## Check service pack version for Windows Vista
SP = get_kb_item("SMB/WinVista/ServicePack");
if(SP && (ver = check_sp(SP)))
{
  if(version_is_less(version:ver, test_version:"2"))
  {
    security_hole(0);
    exit(0);
  }
}

## Check service pack version for Windows Server 2008
SP = get_kb_item("SMB/Win2008/ServicePack");
if(SP && (ver = check_sp(SP)))
{
  if(version_is_less(version:ver, test_version:"2"))
  {
    security_hole(0);
    exit(0);
  }
}

## Check service pack version for Windows 7
SP = get_kb_item("SMB/Win7/ServicePack");
if(SP && (ver = check_sp(SP)))
{
  if(version_is_less(version:ver, test_version:"1"))
  {
    security_hole(0);
    exit(0);
  }
}

## Check service pack version for Windows 2000
SP = get_kb_item("SMB/Win2K/ServicePack");
if(SP && (ver = check_sp(SP)))
{
  if(version_is_less(version:ver, test_version:"4"))
  {
    security_hole(0);
    exit(0);
  }
}
