###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sorinara_audio_player_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Sorinara Streaming Audio Player Stack Overflow Vulnerability
#
# Authors:
# Antu Sanadi<santu@secpod.com>
#
# Modified by: Nikita MR (rnikita@secpod.com)
# Date: 23rd July 2009
# Changes: Added CVE-2009-2568 and updated the  vulnerability insight.
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
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in
  the context of the affected system and cause the application to crash by
  overflowing the stack memory location.";
tag_affected = "Sorinara Streaming Audio Player version 0.9 and prior";
tag_insight = "This vulnerability is due to an improper boundary checks when processing
  playlist 'pla' and '.m3u' files.";
tag_solution = "No solution or patch is available as of 29th May, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.sorinara.com/sap/download.html";
tag_summary = "This host is running Sorinara Streaming Audio Player and is prone
  to Stack Overflow Vulnerability.";

if(description)
{
  script_id(900649);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-29 07:35:11 +0200 (Fri, 29 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1644", "CVE-2009-2568");
  script_bugtraq_id(34861, 34842);
  script_name("Sorinara Streaming Audio Player Stack Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8640");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8625");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50369");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8620");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8617");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50339");

  script_description(desc);
  script_summary("Check for version of Sorinara Streaming Audio Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139,445);
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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SAP\";
vendName = registry_get_sz(key:key, item:"DisplayName");
if("SAP" >< vendName)
{
  readmePath = registry_get_sz(key:key, item:"UninstallString");
  if(!readmePath){
    exit(0);
  }

  readmePath = readmePath - "\uninstall.exe /uninstall";
  readmePath = readmePath + "\Help";

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:readmePath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:readmePath + "\index.htm");
  readmeText = read_file(share:share, file:file, offset:0, count:4500);
  if(!readmeText){
    exit(0);
  }

  sapVer = eregmatch(pattern:"SAP ([0-9.]+)", string:readmeText);
  if(sapVer[1] != NULL)
  {
    if(version_is_less_equal(version:sapVer[1], test_version:"0.9")){
      security_hole(0);
    }
  }
}
