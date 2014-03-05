###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ayeview_gif_dos_vul.nasl 15 2013-10-27 12:49:54Z jan $ 
# 
# AyeView GIF Image Handling Denial of Service Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful remote exploitation could result in Denial of Service.
  Impact Level: Application";
tag_affected = "AyeView version 2.20 and prior on Windows.";
tag_insight = "Flaw is due to an error generated while handling GIF file. These .gif files
  contain a malformed header.";
tag_solution = "No solution or patch is available as of 15th January, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.ayeview.com/";
tag_summary = "The host has AyeView Image Viewer installed and is prone to denial
  of service vulnerability.";

if(description)
{
  script_id(800503);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-15 16:11:17 +0100 (Thu, 15 Jan 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5884");
  script_bugtraq_id(31572);
  script_name("AyeView GIF Image Handling Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?execution=e1s1");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2008-5884");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/497045/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of AyeView");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

verStr = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                             "\Uninstall\AyeView_is1", item:"DisplayName");
if(!verStr){
  exit(0);
}

avVer = eregmatch(pattern:"AyeView version ([0-9.]+)", string:verStr);
if(!avVer[1] != NULL){
  exit(0);
}

if(version_is_less_equal(version:avVer[1], test_version:"2.20")){
  security_warning(0);
}
