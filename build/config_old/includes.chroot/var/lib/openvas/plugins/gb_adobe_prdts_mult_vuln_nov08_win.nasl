###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_vuln_nov08_win.nasl 16 2013-10-27 13:09:52Z jan $
#
# Adobe Reader/Acrobat Multiple Vulnerabilities - Nov08 (Win)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_affected = "Adobe Reader versions 8.1.2 and prior - Windows(All)
  Adobe Acrobat Professional versions 8.1.2 and prior - Windows(All)

  Upgrade to 8.1.3 or higher versions,
  http://www.adobe.com/products/";

tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code
  to cause a stack based overflow via a specially crafted PDF, and could
  also take complete control of the affected system and cause the application
  to crash.
  Impact Level: System";
tag_insight = "The flaws are due to,
  - a boundary error when parsing format strings containing a floating point
    specifier in the util.printf() Javascript function.
  - improper parsing of type 1 fonts.
  - bounds checking not being performed after allocating an area of memory.";
tag_summary = "This host has Adobe Reader/Acrobat installed, which is/are prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(800050);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-05 13:21:04 +0100 (Wed, 05 Nov 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-2992", "CVE-2008-2549", "CVE-2008-4812",
                "CVE-2008-4813", "CVE-2008-4817", "CVE-2008-4816",
                "CVE-2008-4814", "CVE-2008-4815");
  script_bugtraq_id(30035, 32100);
  script_name("Adobe Reader/Acrobat Multiple Vulnerabilities - Nov08 (Win)");
  desc = "

  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected;

  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb08-19.html");
  script_xref(name : "URL" , value : "http://www.coresecurity.com/content/adobe-reader-buffer-overflow");

  script_description(desc);
  script_summary("Check for the version of Adobe Reader/Acrobat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Adobe")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

keys = registry_enum_keys(key:key);

foreach item (keys)
{
  adobeName = registry_get_sz(item:"DisplayName", key:key +item);

  if("Adobe Reader" >< adobeName || "Adobe Acrobat" >< adobeName)
  {
    adobeVer = registry_get_sz(item:"DisplayVersion", key:key + item);
    if(!adobeVer){
      exit(0);
    }

    if(adobeVer =~ "^(7.*|8\.0(\..*)?|8\.1(\.[0-2])?)$"){
      security_hole(0);
    }
    exit(0);
  }
}
