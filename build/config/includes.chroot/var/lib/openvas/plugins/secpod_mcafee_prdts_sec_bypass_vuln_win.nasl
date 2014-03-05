###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mcafee_prdts_sec_bypass_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# McAfee Products Security Bypass Vulnerability (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
##############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to bypass the anti-virus
  scanning and distribute files containing malicious code that the antivirus
  application will fail to detect.
  Impact Level: System/Application";
tag_affected = "McAfee VirusScan
  McAfee Email Gateyway
  McAfee Total Protection
  McAfee Active VirusScan
  McAfee Internet Security
  McAfee Security for Email Servers
  McAfee Security for Microsoft Sharepoint
  McAfee SecurityShield for Microsoft ISA Server
  McAfee software that uses DAT files prior to 5600 on Windows";
tag_insight = "Error in AV Engine fails to handle specially crafted packets via,
  - an invalid Headflags and Packsize fields in a malformed RAR archive.
  - an invalid Filelength field in a malformed ZIP archive.";
tag_solution = "Updates are available through DAT files 5600 or later
  http://www.mcafee.com/apps/downloads/security_updates/dat.asp";
tag_summary = "This host is installed with McAfee products and are prone to
  Security Bypass vulnerability.";

if(description)
{
  script_id(900656);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-26 15:05:11 +0200 (Tue, 26 May 2009)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-1348");
  script_bugtraq_id(34780);
  script_name("McAfee Products Security Bypass Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34949");
  script_xref(name : "URL" , value : "http://blog.zoller.lu/2009/04/case-for-av-bypassesevasions.html");
  script_xref(name : "URL" , value : "http://blog.zoller.lu/2009/04/mcafee-multiple-bypassesevasions-ziprar.html");
  script_xref(name : "URL" , value : "https://kc.mcafee.com/corporate/index?page=content&amp;id=SB10001&amp;actp=LIST_RECENT");

  script_description(desc);
  script_summary("Check for the version of Scan Engine DAT file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
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

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

datName = registry_get_sz(key:"SOFTWARE\McAfee\AVEngine", item:"DAT");
if("McAfee" >< datName)
{
  datVer = registry_get_dword(key:"SOFTWARE\McAfee\AVEngine",
                              item:"AVDatVersion");
  datVer = eregmatch(pattern:"([0-9]+)", string:datVer);
  if(datVer[1] != NULL)
  {
    if(version_is_less(version:datVer[1], test_version:"5600")){
      security_hole(0);
    }
  }
}
