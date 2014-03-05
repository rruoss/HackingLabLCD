###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_office_prdts_insecure_lib_load_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Office Products Insecure Library Loading Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow the attackers to execute arbitrary code and
  conduct DLL hijacking attacks.
  Impact Level: Application";
tag_affected = "Microsoft Visio 2003.
  Microsoft Office Groove 2007.
  Microsoft Office PowerPoint 2007/2010.";
tag_insight = "The flaw is due to the application insecurely loading certain librairies
  from the current working directory, which could allow attackers to execute
  arbitrary code by tricking a user into opening a file from a network share.";
tag_solution = ": No solution or patch is available as of 27th September, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/downloads/en/default.aspx";
tag_summary = "This host is installed with microsoft product(s) and is prone to
  insecure library loading vulnerability.";

if(description)
{
  script_id(902254);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_cve_id("CVE-2010-3141", "CVE-2010-3142", "CVE-2010-3146", "CVE-2010-3148");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft Office Products Insecure Library Loading Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14723/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14782/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14746/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14744/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2188");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2192");

  script_description(desc);
  script_summary("Check for the Office products version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows");
  script_dependencies("secpod_office_products_version_900032.nasl",
                      "secpod_ms_office_detection_900025.nasl");
  script_require_keys("SMB/WindowsVersion", "SMB/Office/Publisher/Version");
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
include("secpod_smb_func.inc");


## Check for Office
officeVer = get_kb_item("MS/Office/Ver");
if(!officeVer){
  exit(0);
}

## Check for Office power point
ppntVer = get_kb_item("SMB/Office/PowerPnt/Version");
if(ppntVer && (ppntVer =~ "^(12|14)\..*"))
{
  security_hole(0);
  exit(0);
}

## check for office groove
mGVer = get_kb_item("SMB/Office/Groove/Version");
if(mGVer && (mGVer =~ "^12\..*"))
{
  security_hole(0);
  exit(0);
}

## check for  Office Visio
ovPath = registry_get_sz(item:"Path",
         key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\visio.exe");

if(!ovPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ovPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:ovPath + "visio.exe");

exeVer = GetVer(file:file, share:share);
if(!exeVer){
  exit(0);
}

if(exeVer && (exeVer =~ "^11\..*")){
  security_hole(0);
}
