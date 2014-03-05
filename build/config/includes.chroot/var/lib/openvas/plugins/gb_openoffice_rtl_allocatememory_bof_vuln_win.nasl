###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openoffice_rtl_allocatememory_bof_vuln_win.nasl 16 2013-10-27 13:09:52Z jan $
#
# OpenOffice rtl_allocateMemory Heap Based BOF Vulnerability
#
# Authors:      Chandan S <schandan@secpod.com>
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
tag_impact = "Exploitation will result in buffer overflows via a specially crafted document
  and allow remote unprivileged user who provides a OpenOffice.org document that
  is opened by a local user to execute arbitrary commands on the system with the
  privileges of the user running OpenOffice.org.
  Impact Level: System";
tag_solution = "Upgrade to OpenOffice 2.4.1
  http://download.openoffice.org/index.html";

tag_affected = "OpenOffice.org 2.x on Windows (Any).";
tag_insight = "The flaw is in alloc_global.c file in which rtl_allocateMemory function
  rounding up allocation requests to be aligned on a 8 byte boundary without
  checking the rounding results, in an integer overflow condition.";
tag_summary = "The host has OpenOffice installed which is prone to heap based
  buffer overflow vulnerability.";

if(description)
{
  script_id(800009);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-01 17:01:16 +0200 (Wed, 01 Oct 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-2152");
  script_bugtraq_id(29622);
  script_xref(name:"CB-A", value:"08-0095");
  script_name("OpenOffice rtl_allocateMemory Heap Based BOF Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/30599");
  script_xref(name : "URL" , value : "http://www.openoffice.org/security/cves/CVE-2008-2152.html");
  script_xref(name : "URL" , value : "http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=714");

  script_description(desc);
  script_summary("Check for the version of OpenOffice");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
keys = registry_enum_keys(key);
foreach item (keys)
{
  if("OpenOffice.org" >< registry_get_sz(key:key + item, item:"DisplayName"))
  {
    if((egrep(pattern:"^([01]\..*|2\.([0-3](\..*)?|4(\.([0-8]?[0-9]?" +
                      "[0-9]?[0-9]|9[0-2][0-9][0-9]|930[0-9]))?))$",
              string:registry_get_sz(key:key + item, item:"DisplayVersion")))){
      security_hole(0);
    }
    exit(0);
  }
}
