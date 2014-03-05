###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_winasm_studio_wap_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# WinAsm Studio Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in
  the context of the application to cause heap overflow.

  Impact level: System/Application";

tag_affected = "WinAsm Studio version 5.1.5.0 and prior.";
tag_insight = "Improper boundary checking while handling project files which leads to
  heap overflow while processing crafted '.wap' files.";
tag_solution = "No solution or patch is available as of 26th March, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.winasm.net";
tag_summary = "This host is running WinAsm Studio and is prone to Heap Overflow
  Vulnerability.";

if(description)
{
  script_id(900532);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1040");
  script_bugtraq_id(34132);
  script_name("WinAsm Studio Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34309");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8224");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49266");

  script_description(desc);
  script_summary("Check for the version of WinAsm Studio");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

progDir = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\",
                           item:"ProgramFilesDir");
if(!progDir){
  exit(0);
}

winasmPath1 = progDir + "\WinAsm\WinAsm.exe";
winasmPath2 = progDir - "Program Files" + "\WinAsm\WinAsm.exe";

foreach path (make_list(winasmPath1, winasmPath2))
{
  share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$",string:path);
  file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1",string:path);
  version = GetVer(file:file, share:share);
  if(version != NULL)
  {
    if(version_is_less_equal(version:version, test_version:"5.1.5.0")){
      security_hole(0);
    }
    exit(0);
  }
}
