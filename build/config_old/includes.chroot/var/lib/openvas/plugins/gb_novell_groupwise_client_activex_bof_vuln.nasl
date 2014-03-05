###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_groupwise_client_activex_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Novell Groupwise Client ActiveX Control Buffer Overflow Vulnerability
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
tag_solution = "No solution or patch is available as of 09th November, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For further updates refer, http://www.novell.com/products/groupwise/

  Workaround:
  Set the Killbit for the vulnerable CLSID
  http://support.microsoft.com/kb/240797";

tag_impact = "Successful expoitation will allow remote attackers to execute arbitrary
  code on the affected system and may crash the client.";
tag_affected = "Novell GroupWise Client 7.0.3.1294 and prior on Windows.";
tag_insight = "A boundary error occurs in Novell Groupwise Client ActiveX control (gxmim1.dll)
  while handling overly long arguments passed to the 'SetFontFace()' method.";
tag_summary = "This host is installed with Novell Groupwise Client ActiveX Control
  and is prone to Buffer Overflow vulnerability.";

if(description)
{
  script_id(800973);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-09 14:01:44 +0100 (Mon, 09 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3863");
  script_bugtraq_id(36398);
  script_name("Novell Groupwise Client ActiveX Control Buffer Overflow Vulnerability");
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

  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9683");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/387373.php");

  script_description(desc);
  script_summary("Check the version of Novell Groupwise Client ActiveX control");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_require_keys("Novell/Groupwise/Client/Win/Ver");
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

gcVer = get_kb_item("Novell/Groupwise/Client/Win/Ver");
if(gcVer == NULL){
  exit(0);
}

if(version_is_less_equal(version:gcVer, test_version:"7.0.3.1294"))
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion"+
                                "\App Paths\GrpWise.exe", item:"Path");
  if(dllPath == NULL){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$", string:dllPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",  string:dllPath+
                                                          "\gxmim1.dll");
  dllVer = GetVer(share:share, file:file);

  # Check if gxmim1.dll version is 7.0.3.1294 or prior
  if(version_is_less_equal(version:dllVer, test_version:"7.0.3.1294"))
  {
    # Check if the Killbits are set
    if(is_killbit_set(clsid:"{9796BED2-C1CF-11D2-9384-0008C7396667}") == 0){
      security_warning(0);
    }
  }
}
