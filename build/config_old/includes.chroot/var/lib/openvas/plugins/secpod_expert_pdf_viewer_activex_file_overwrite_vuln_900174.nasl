##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_expert_pdf_viewer_activex_file_overwrite_vuln_900174.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Visagesoft eXPert PDF Viewer ActiveX Control File Overwrite Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow to overwrite arbitrary files.
  Impact Level: Application";
tag_affected = "Visagesoft eXPert PDF Viewer ActiveX Control versions 3.0.990.0 and prior";
tag_insight = "The flaw is due to insecure method, 'savePageAsBitmap()' in VSPDFViewerX.ocx
  ActiveX Control. This can be exploited to corrupt arbitrary files on the local
  system via arguments passed to the affected method.";
tag_solution = "Set the kill-bit for the CLSID {BDF3E9D2-5F7A-4F4A-A914-7498C862EA6A}.
  No solution or patch is available as of 06rd November, 2008.";
tag_summary = "The host is installed with eXPert PDF Viewer ActiveX and is prone
  to ActiveX Control based file overwrite vulnerability.";

if(description)
{
  script_id(900174);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_bugtraq_id(31984);
  script_cve_id("CVE-2008-4919");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_category(ACT_GATHER_INFO);
  script_family("Remote file access");
  script_name("Visagesoft eXPert PDF Viewer ActiveX Control File Overwrite Vulnerability");
  script_summary("Check for vulnerable version of eXPert PDF Viewer ActiveX");
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
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/6875");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32426");

  script_description(desc);
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
include("secpod_smb_func.inc");


if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
enumKeys = registry_enum_keys(key);

if(!enumKeys){
  exit(0);
} 

foreach entry (enumKeys)
{
  if("eXPert PDF ViewerX" ><
     registry_get_sz(key: key + entry, item:"DisplayName"))
  {
    # Grep for version 3.0.990.0 and prior
    if(egrep(pattern:"^([0-2](\..*)?|3\.(0(\.[0-8]?[0-9]?[0-9](\..*)?|\.9" +
                     "[0-8][0-9](\..*)?|\.990(\.0)?)?))$",
             string:registry_get_sz(key: key + entry, item:"DisplayVersion")))
    {
      # Check for Kill-Bit set for ActiveX control
      clsid = "{BDF3E9D2-5F7A-4F4A-A914-7498C862EA6A}";
      regKey = "SOFTWARE\Classes\CLSID\" + clsid;
      if(registry_key_exists(key:regKey))
      {
        activeKey = "SOFTWARE\Microsoft\Internet Explorer\" +
                    "ActiveX Compatibility\" + clsid;
        killBit = registry_get_dword(key:activeKey, item:"Compatibility Flags");
        if(killBit && (int(killBit) == 1024)){
          exit(0);
        }
        security_hole(0);
      }
    }
    exit(0);
  }
}
