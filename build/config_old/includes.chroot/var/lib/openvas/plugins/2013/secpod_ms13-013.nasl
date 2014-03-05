###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-013.nasl 11 2013-10-27 10:12:02Z jan $
#
# Microsoft FAST Search Server 2010 SharePoint RCE Vulnerabilities (2784242)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could run arbitrary code in the context of a user
  account with a restricted token.
  Impact Level: System/Application";

tag_affected = "Microsoft FAST Search Server 2010 for SharePoint Service Pack 1";
tag_insight = "The flaws are due to the error in Oracle Outside In libraries, when
  used by the Advanced Filter Pack while parsing specially crafted files.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-013";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-013.";

if(description)
{
  script_id(902949);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-3214", "CVE-2012-3217");
  script_bugtraq_id(55977, 55993);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-13 11:28:37 +0530 (Wed, 13 Feb 2013)");
  script_name("Microsoft FAST Search Server 2010 SharePoint RCE Vulnerabilities (2784242)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52136/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2553234");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms13-013");

  script_description(desc);
  script_summary("Check for the vulnerable 'Vseshr.dll' file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl",
                      "gb_ms_fast_search_server_detect.nasl");
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

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Variables Initialization
path = "";
dllPath = "";
dllVer = "";

## SharePoint Server 2010
path = get_kb_item("MS/SharePoint/Install/Path");
if(!path){
  exit(0);
}

dllPath = path + "bin";
dllVer = fetch_file_version(sysPath:dllPath,
         file_name:"Vseshr.dll");
if(!dllVer){
  exit(0);
}

if(version_in_range(version:dllVer, test_version:"8.3.7.000", test_version2:"8.3.7.206")){
  security_warning(0);
}
