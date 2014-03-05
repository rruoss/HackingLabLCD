###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_visual_studio_insecure_lib_load_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Visual Studio Insecure Library Loading Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow the attackers to execute arbitrary code
  and conduct DLL hijacking attacks.
  Impact Level: Application";
tag_affected = "Microsoft Visual Studio";
tag_insight = "The flaw is due to 'ATL MFC Trace Tool'(AtlTraceTool8.exe) loading
  libraries in an insecure manner. This can be exploited to load arbitrary
  libraries by tricking a user into opening a TRC file located on a remote
  WebDAV or SMB share.";
tag_solution = "No solution or patch is available as of 27th September, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/downloads/en/default.aspx";
tag_summary = "This host is installed with Microsoft Visual Studio and is prone to
  insecure library loading vulnerability.

  This NVT has been replaced by NVT secpod_ms11-025.nasl
  (OID:1.3.6.1.4.1.25623.1.0.900285).";

if(description)
{
  script_id(902255);
  script_version("$Revision: 14 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_cve_id("CVE-2010-3190");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft Visual Studio Insecure Library Loading Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41212");
  script_xref(name : "URL" , value : "http://www.corelan.be:8800/index.php/2010/08/25/dll-hijacking-kb-2269637-the-unofficial-list/");

  script_description(desc);
  script_summary("Check for the Microsoft Visual Studio version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows");
  script_dependencies("secpod_ms_visual_prdts_detect.nasl");
  script_require_keys("Microsoft/VisualStudio/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms11-025.nasl

include("smb_nt.inc");

## Check for Visual studio installation
vsVer = get_kb_item("Microsoft/VisualStudio/Ver");
if(vsVer){
 security_hole(0);
}
