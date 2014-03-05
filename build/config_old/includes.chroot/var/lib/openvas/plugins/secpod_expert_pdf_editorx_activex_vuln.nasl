###############################################################################
# OpenVAS Vulnerability Test
# $Id:secpod_expert_pdf_editorx_activex_vuln.nasl 1068 2009-03-24 19:50:24Z mar $
#
# Expert PDF EditorX ActiveX File Overwrite Vulnerability
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
tag_affected = "Expert PDF EditorX 'VSPDFEditorX.ocx' version 1.0.1910.0 and prior.

  Workaround:
  Set the Killbit for the vulnerable CLSID {89F968A1-DBAC-4807-9B3C-405A55E4A279}
  http://support.microsoft.com/kb/240797";

tag_impact = "Successful exploitation will let the attacker corrupt or overwrite
  arbitrary files on the user's system.
  Impact Level: System/Application";
tag_insight = "This flaw is due to an ActiveX control in Expert PDF EditorX file
  'VSPDFEditorX.ocx' providing insecure 'extractPagesToFile' method.";
tag_solution = "No solution or patch is available as of 26th March, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.visagesoft.com/products/pdfeditorx";
tag_summary = "This host is installed with Expert PDF EditorX and is
  prone to ActiveX file overwrite vulnerability.";

if(description)
{
  script_id(900481);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-6496");
  script_bugtraq_id(32664);
  script_name("Expert PDF EditorX ActiveX File Overwrite Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32990");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7358");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/47166");

  script_description(desc);
  script_summary("Check for the 'VSPDFEditorX.ocx' Version and Killbit");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  editorx = registry_get_sz(key:key + item, item:"DisplayName");
  if("eXPert PDF EditorX" >< editorx)
  {
    ocxVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    break;
  }
}

if(ocxVer != NULL)
{
  # Grep for VSPDFEditorX.ocx version 1.0.1910.0 and prior
  if(version_is_less_equal(version:ocxVer, test_version:"1.0.1910.0"))
  {
    if(is_killbit_set(clsid:"{89F968A1-DBAC-4807-9B3C-405A55E4A279}") == 0){
      security_hole(0);
    }
  }
}
