###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-053.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft Bluetooth Stack Remote Code Execution Vulnerability (2566220)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com>
#  - Used WMI functions to get the file version
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
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms11-053

  ******
  NOTE:  Ignore this warning if 'Windows Vista Feature Pack for Wireless'
         is not installed on Windows Vista Service Pack 1
  ******";

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM-level privileges.
  Impact Level: System";
tag_affected = "Microsoft Windows Vista Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior";
tag_insight = "The flaw is due to the way an object in memory is accessed when it has
  not been correctly initialized or has been deleted.";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-053.";

if(description)
{
  script_id(902395);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)");
  script_cve_id("CVE-2011-1265");
  script_bugtraq_id(48617);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft Bluetooth Stack Remote Code Execution Vulnerability (2566220)");
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

  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2532531");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms11-053");

  script_description(desc);
  script_summary("Check for vulnerable file 'fsquirt.exe' version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "smb_login.nasl");
  script_require_keys("SMB/login","SMB/password");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("secpod_reg.inc");
include("version_func.inc");

## Variables Initialization
host = "";
usrname = "";
passwd = "";
handle = "";
ver = "";
fileVer = "";
flag = FALSE;

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win7:2, win7x64:2) <= 0){
  exit(0);
}

## Get host
host    = get_host_ip();

usrname = get_kb_item("SMB/login");
passwd  = get_kb_item("SMB/password");

if(!host || !usrname || !passwd){
  exit(0);
}

## Get the handle to execute wmi query
handle = wmi_connect(host:host, username:usrname, password:passwd);

if(!handle){
  exit(0);
}

## WMI query to grep the file version
query = 'Select Version from CIM_DataFile Where FileName ='
        + raw_string(0x22) +'fsquirt' +raw_string(0x22) + ' AND Extension ='
        + raw_string(0x22) +'exe' + raw_string(0x22);

fileVer = wmi_query(wmi_handle:handle, query:query);
if(!fileVer){
  exit(0);
}

foreach ver (split(fileVer))
{
  ver = eregmatch(pattern:"\fsquirt.exe.?([0-9.]+)", string:ver);
  if(ver[1])
  {
    ## Checking for Windows Vista
    if(hotfix_check_sp(winVista:3) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");

      if("Service Pack 1" >< SP)
      {
        ## Check for fsquirt.exe ver < 6.1.6001.22204
        if(version_is_greater_equal(version:ver[1], test_version:"6.1.6001.22204"))
        {
          flag = TRUE;
          break ;
        }
      }

      if("Service Pack 2" >< SP)
      {
        ## Check for fsquirt.exe
        if(version_in_range(version:ver[1], test_version:"6.0.6002.18005", test_version2:"6.0.6002.21999")||
           version_is_greater_equal(version:ver[1], test_version:"6.0.6002.22629"))
        {
          flag = TRUE;
          break ;
        }
      }
    }

    ## Windows 7
    if(hotfix_check_sp(win7:2, win7x64:2) > 0)
    {
      if(version_in_range(version:ver[1], test_version:"6.1.7600.16385", test_version2:"6.1.7600.19999") ||
         version_is_greater_equal(version:ver[1], test_version:"6.1.7601.17514"))
      {
        flag = TRUE;
        break ;
      }
    }
  }
}

if(!flag){
  security_hole(0);
}
