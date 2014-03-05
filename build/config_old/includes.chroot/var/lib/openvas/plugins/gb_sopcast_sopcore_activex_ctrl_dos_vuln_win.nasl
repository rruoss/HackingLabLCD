###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sopcast_sopcore_activex_ctrl_dos_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# SopCast SopCore ActiveX Control DoS Vulnerability (Win)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_solution = "Upgrade to SopCast version 3.2.9 or later
  For updates refer to http://www.sopcast.org/

  Workaround:
  Set the killbit for the CLSID {8FEFF364-6A5F-4966-A917-A3AC28411659}
  http://support.microsoft.com/kb/240797";

tag_impact = "Attacker may exploit this issue to execute arbitrary script code and may
  crash the browser.
  Impact Level: Application";
tag_affected = "SopCast sopocx.ocx version 3.0.3.501 on Windows.";
tag_insight = "Remote arbitrary programs can be executed via executable file name in the
  SetExternalPlayer function of the sopocx.ocx file and persuading a victim
  to visit a specially-crafted Web page.";
tag_summary = "This host is installed with SopCast SopCore ActiveX and is prone
  to denial of service vulnerability.";

if(description)
{
  script_id(800530);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-12 08:39:03 +0100 (Thu, 12 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0811");
  script_bugtraq_id(33920);
  script_name("SopCast SopCore ActiveX Control DoS Vulnerability (Win)");
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

  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/8143");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/48955");

  script_description(desc);
  script_summary("Check for the Version of SopCast SopCore ActiveX");
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
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

sopName = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                  "\Uninstall\SopCast", item:"DisplayName");
if("SopCast" >< sopName)
{
  sopPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                "\Uninstall\SopCast", item:"DisplayIcon");
  if(!sopPath){
    exit(0);
  }

  sopPath = sopPath - "SopCast.exe" + "sopocx.ocx";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sopPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sopPath);
  sopocxVer = GetVer(share:share, file:file);

  # Check for version of sopocx.ocx
  if(sopocxVer != NULL &&
     version_is_equal(version:sopocxVer, test_version:"3.0.3.501"))
  {
    if(is_killbit_set(clsid:"{8FEFF364-6A5F-4966-A917-A3AC28411659}") == 0){
      security_hole(0);
    }
  }
}
