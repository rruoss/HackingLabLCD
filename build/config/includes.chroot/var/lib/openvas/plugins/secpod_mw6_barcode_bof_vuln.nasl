###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mw6_barcode_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# MW6 Technologies Barcode ActiveX Buffer Overflow Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_affected = "Barcode ActiveX (Barcode.dll) version 3.0.0.1 and prior

  Workaround:
  Set the Killbit for the vulnerable CLSID
  http://support.microsoft.com/kb/240797";

tag_impact = "Successful exploitation will let the attacker cause a heap buffer overflow
  via an overly long string assigned to the Supplement property.
  Impact Level: System/Application";
tag_insight = "ActiveX control in Barcode.dll due to a boundary error in the
  Barcode.MW6Barcode.1.";
tag_solution = "No solution or patch is available as of 30th January, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For further updates refer, http://mw6tech.com/download.html";
tag_summary = "This host is installed with MW6 Technologies Barcode ActiveX and
  is prone to Buffer Overflow Vulnerability.";

if(description)
{
  script_id(900455);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-02 05:02:24 +0100 (Mon, 02 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0298");
  script_bugtraq_id(33451);
  script_name("MW6 Technologies Barcode ActiveX Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33663");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7869");

  script_description(desc);
  script_summary("Check for the Barcode Library File version and kill bit");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
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

if(!registry_key_exists(key:"SOFTWARE\Classes\Barcode.MW6Barcode")){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\Barcode.dll");

dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

# Grep for Barcode.dll version 3.0.0.1 and prior.
if(version_is_less_equal(version:dllVer, test_version:"3.0.0.1"))
{
  # Workaround Check
  if(!is_killbit_set(clsid:"{14D09688-CFA7-11D5-995A-005004CE563B}")){
    security_hole(0);
  }
}
