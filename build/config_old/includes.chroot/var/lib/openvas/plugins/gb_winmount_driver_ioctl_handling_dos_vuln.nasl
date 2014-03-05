###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_winmount_driver_ioctl_handling_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# WinMount 'WMDrive.sys' Driver IOCTL Handling Denial of Service Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to cause the application
  to crash.
  Impact Level: Application";
tag_affected = "WinMount version 3.5.1018 and prior.";
tag_insight = "The flaw is due to a null pointer dereference error in WMDrive.sys,
  when processing a crafted '0x87342000 IOCTL' in the WMDriver device.";
tag_solution = "No solution or patch is available as of 6th January, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.winmount.com/index.html";
tag_summary = "This host is installed with WinMount and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(802372);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-5032");
  script_bugtraq_id(51034);
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-06 11:24:26 +0530 (Fri, 06 Jan 2012)");
  script_name("WinMount 'WMDrive.sys' Driver IOCTL Handling Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/77747");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46872/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71764");

  script_description(desc);
  script_summary("Check for the version of WinMount");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
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

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Get version from Registry
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinMount_is1";
if(!registry_key_exists(key:key)){
  exit(0);
}

wmountName = registry_get_sz(key:key , item:"DisplayName");
if("WinMount" >< wmountName)
{
  wmountVer = registry_get_sz(key:key , item:"DisplayVersion");

  if(wmountVer != NULL)
  {
    ## Check for wmountVer version <= 3.5.1018
    if(version_is_less_equal(version:wmountVer, test_version:"3.5.1018"))
    {
      ## Get System Path
      sysPath = smb_get_systemroot();
      if(!sysPath ){
         exit(0);
      }

      ## Get Version from WMDrive.sys
      sysVer = fetch_file_version(sysPath, file_name:"system32\WMDrive.sys");

      if(!isnull(sysVer))
      {
        if(version_is_less_equal(version:sysVer, test_version:"3.4.181.224"))
        {
          security_warning(0);
          exit(0);
        }
      }
    }
  }
}
