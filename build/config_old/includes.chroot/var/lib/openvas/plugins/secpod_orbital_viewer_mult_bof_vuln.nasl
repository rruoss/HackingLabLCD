###############################################################################
# OpenVAS Vulnerabilities Test
# $Id: secpod_orbital_viewer_mult_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Orbital Viewer File Processing Buffer Overflow Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_summary = "This host has Orbital Viewer installed and is prone to buffer
  overflow vulnerabilities.

  Vulnerabilities Insight:
  The flaw is due to error within the processing of '.orb' and '.ov' files,
  which can be exploited to cause a stack-based buffer overflow when a user is
  tricked into opening a specially crafted '.orb' or '.ov' file.";

tag_impact = "Successful exploitation will allow attackers to cause buffer overflow
  and execute arbitrary code on the system by tricking a user into opening
  a malicious file or cause the affected application to crash.
  Impact Level: Application";
tag_affected = "Orbital Viewer version 1.04";
tag_solution = "No solution or patch is available as of 24th March, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.orbitals.com/orb/index.html";

if(description)
{
  script_id(900755);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2010-0688");
  script_bugtraq_id(38436);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Orbital Viewer File Processing Buffer Overflow Vulnerabilities");
  desc = "
  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://www.osvdb.org/62580");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38720");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0478");
  script_xref(name : "URL" , value : "http://www.corelan.be:8800/index.php/forum/security-advisories/corelan-10-011-orbital-viewer-orb-buffer-overflow/");

  script_description(desc);
  script_summary("Check for the version of Orbital Viewer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Orbital Viewer";
orbitName = registry_get_sz(key:key, item:"DisplayName");

if("Orbital Viewer" >< orbitName)
{
  orbitPath = registry_get_sz(key:key + item, item:"UninstallString");
  if(orbitPath != NULL)
  {
    share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$",string:orbitPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1", string:orbitPath -
                                "\UNINST.EXE" + "\ov.exe");
    orbitVer = GetVer(share:share, file:file);
    if(orbitVer != NULL)
    {
      # Check if the version is  1.04 (1.0.0.2)
      if(version_is_less_equal(version:orbitVer, test_version:"1.0.0.2")){
        security_hole(0);
      }
    }
  }
}
