##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_chilkat_crypt_activex_cntl_vuln_900171.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Chilkat Crypt ActiveX Control 'ChilkatCrypt2.dll' File Overwrite Vulnerability
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
tag_impact = "Successful exploitation will allow execution of arbitrary code.
  Impact Level: Application";
tag_affected = "Chilkat Crypt ActiveX Component version 4.3.2.1 and prior";
tag_insight = "The vulnerability is due to the error in the 'ChilkatCrypt2.dll' ActiveX
  Control component that does not restrict access to the 'WriteFile()' method.";
tag_solution = "Set the kill-bit for the CLSID {3352B5B9-82E8-4FFD-9EB1-1A3E60056904}.
  No solution or patch is available as of 05th November, 2008.";
tag_summary = "The host is installed Chilkat Crypt, which is prone to ActiveX
  Control based arbitrary file overwrite vulnerability.";

if(description)
{
  script_id(900171);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-11 15:58:44 +0100 (Tue, 11 Nov 2008)");
  script_cve_id("CVE-2008-5002");
 script_bugtraq_id(32073);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_name("Chilkat Crypt ActiveX Control 'ChilkatCrypt2.dll' File Overwrite Vulnerability");
  script_summary("Check for vulnerable version of Chilkat Crypt");
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
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/6963");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32513/");

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
  if("Chilkat Crypt ActiveX" ><
     registry_get_sz(key: key + entry, item:"DisplayName"))
  {
    # Grep for version 4.3.2.1 and prior
    if(egrep(pattern:"^4\.([0-2](\..*)?|3(\.[0-2](\.[01])?)?)$",
             string:registry_get_sz(key: key + entry, item:"DisplayVersion")))
    {
      # Check if Kill-Bit is set for ActiveX control
      clsid = "{3352B5B9-82E8-4FFD-9EB1-1A3E60056904}";
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
