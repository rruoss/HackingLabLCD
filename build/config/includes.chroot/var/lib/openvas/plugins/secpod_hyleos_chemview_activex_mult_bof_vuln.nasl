###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hyleos_chemview_activex_mult_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Hyleos ChemView ActiveX Control Multiple Buffer Overflow Vulnerabilities
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
tag_affected = "Hyleos ChemView ActiveX Control version 1.9.5.1 and prior.

  Workaround:
  Set the Killbit for the vulnerable CLSID {C372350A-1D5A-44DC-A759-767FC553D96C}";

tag_impact = "Successful exploitation could allow an attacker to execute arbitrary code
  within the context of the affected application.
  Impact Level: Application";
tag_insight = "The flaws are due to two boundary errors in the 'HyleosChemView.ocx'
  which can be exploited to cause stack-based buffer overflows by passing
  strings containing an overly large number of white-space characters to the
  'SaveasMolFile()' and 'ReadMolFile()' methods.";
tag_solution = "No solution or patch is available as of 25th February, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.hyleos.net/?s=applications&p=ChemView";
tag_summary = "This host is installed with Hyleos ChemView ActiveX Control and is
  prone to multiple Buffer Overflow vulnerabilities.";

if(description)
{
  script_id(900749);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-02 12:02:59 +0100 (Tue, 02 Mar 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2010-0679");
  script_bugtraq_id(38225);
  script_name("Hyleos ChemView ActiveX Control Multiple Buffer Overflow Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38523");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/11422");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1002-advisories/chemviewx-overflow.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1002-exploits/hyleoschemview-heap.rb.txt");

  script_description(desc);
  script_summary("Check for the HyleosChemView.ocx Version and Killbit");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_hyleos_chemview_detect.nasl");
  script_require_keys("Hyleos/ChemViewX/Ver");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

chemVer = get_kb_item("Hyleos/ChemViewX/Ver");
if(!chemVer){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
      exit(0);
}

if(!version_is_less_equal(version:chemVer, test_version:"1.9.5.1")){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("Hyleos - ChemViewX" >< name)
  {
    chemPath = registry_get_sz(key:key + item, item:"InstallLocation");
    dllPath = chemPath + "\Common\HyleosChemView.ocx";

    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

    dllVer = GetVer(file:file, share:share);
    if(dllVer != NULL)
    {
      # Grep for HyleosChemView.ocx version 1.9.5.1 and prior
      if(version_is_less_equal(version:dllVer, test_version:"1.9.5.1"))
      {
        # Workaround check
        if(is_killbit_set(clsid:"{C372350A-1D5A-44DC-A759-767FC553D96C}") == 0){
          security_hole(0);
        }
      }
    }
  }
}
