###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aol_activex_remote_code_exec_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# AOL SuperBuddy ActiveX Control Remote Code Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_solution = "No solution or patch is available as of 22nd October, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.aol.com/

  Workaround:
  Set the kill-bit for the CLSID {189504B8-50D1-4AA8-B4D6-95C8F58A6414}
  http://support.microsoft.com/kb/240797";

tag_impact = "Successful exploitation will let the attacker execute arbitrary code by
  tricking a user into visiting a specially crafted web page or compromise
  an affected system.
  Impact Level: System/Application";
tag_affected = "America Online (AOL) version 9.5.0.1 and prior";
tag_insight = "The flaw is due to a use-after-free error in the 'Sb.SuperBuddy.1'
  ActiveX control in sb.dll. This can be exploited to cause a memory corruption
  via malformed arguments passed to the 'SetSuperBuddy()' ActiveX method.";
tag_summary = "This host is installed with AOL ActiveX and is prone to remote code
  execution vulnerability.";

if(description)
{
  script_id(801026);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3658");
  script_bugtraq_id(36580);
  script_name("AOL SuperBuddy ActiveX Control Remote Code Execution Vulnerability");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/36919");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2812");
  script_xref(name : "URL" , value : "http://retrogod.altervista.org/9sg_aol_91_superbuddy.html");

  script_description(desc);
  script_summary("Check for the AOL sb.dll version and CLSID");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_aol_detect.nasl");
  script_require_keys("AOL/Ver");
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

if(!(get_kb_item("AOL/Ver") =~ "^9\..*")){
  exit(0);
}

appPath = registry_get_sz(key:"SOFTWARE\America Online\AOL\CurrentVersion",
                          item:"AppPath");
if(appPath != NULL )
{
  share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$", string:appPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1",
                      string:appPath + "\sb.dll" );
  dllVer = GetVer(file:file, share:share);
  if(!dllVer){
    exit(0);
  }

  # Check for version of sb.dll
  if(version_is_less_equal(version:dllVer, test_version:"9.5.0.1"))
  {
    if(is_killbit_set(clsid:"{189504B8-50D1-4AA8-B4D6-95C8F58A6414}") == 0){
      security_hole(0);
    }
  }
}
