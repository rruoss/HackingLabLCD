###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_euphonics_player_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Euphonics Audio Player Buffer Overflow Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application through crafted playlist files 'file.pls' with
  overly long data which may lead to crashing of the application.

  Impact level: Application/System";

tag_affected = "Euphonics Audio Player with AdjMmsEng.dll file version 7.11.2.7 and prior.";
tag_insight = "The vulnerability exists in AdjMmsEng.dll file of multiple MultiMedia Soft
  audio components for .NET. This flaw arises due to failure in performing
  adequate boundary checks on user supplied input to the application buffer.";
tag_solution = "Upgrade to the latest version
  http://sourceforge.net/projects/euphonics";
tag_summary = "This host is running Euphonics Audio Player and is prone to Buffer
  Overflow Vulnerability.";

if(description)
{
  script_id(900459);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_bugtraq_id(33589);
  script_cve_id("CVE-2009-0476");
  script_name("Euphonics Audio Player Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/Advisories/33817");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33791");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7958");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7973");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7974");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/0316");

  script_description(desc);
  script_summary("Check for the version of Euphonics Audio Player");
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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

key2 = "SOFTWARE\Microsoft\Windows\CurrentVersion\";

foreach item (registry_enum_keys(key:key))
{
  value = registry_get_sz(key:key + item, item:"DisplayName");
  if("Euphonics" >< value)
  {
    progDir =  registry_get_sz(key:key2, item:"ProgramFilesDir");
    phonicsPath = progDir + "\Euphonics\AdjMmsEng.dll";
    break;
  }
}

if(!progDir){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$",string:phonicsPath);
file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1",string:phonicsPath);

version = GetVer(file:file, share:share);
if(version == NULL){
  exit(0);
}
# Grep for 'AdjMmsEng.dll' version less or equal to 7.11.2.7
if(version_is_less_equal(version:version, test_version:"7.11.2.7")){
  security_hole(0);
}
