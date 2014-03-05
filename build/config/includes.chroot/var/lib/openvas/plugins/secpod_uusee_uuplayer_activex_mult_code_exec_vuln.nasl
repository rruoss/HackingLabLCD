###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_uusee_uuplayer_activex_mult_code_exec_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# UUSee UUPlayer ActiveX Control Multiple Remote Code Execution Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code in
  the context of the application using the ActiveX control. Failed exploit
  attempts will likely result in denial-of-service conditions.
  Impact Level: System/Application";
tag_affected = "UUSee UUPlayer 2010 6.11.0609.2";
tag_insight = "- A boundary error in the UUPlayer ActiveX control when handling the
   'SendLogAction()' method can be exploited to cause a heap-based buffer
   overflow via an overly long argument.
  - An input validation error in the UUPlayer ActiveX control when handling
    the 'Play()' method can be exploited to execute an arbitrary program via
    a UNC path passed in the 'MPlayerPath' parameter.";
tag_solution = "No solution or patch is available as of 30th August, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://download.uusee.com/";
tag_summary = "This host is installed with UUSee UUPlayer and is prone to multiple
  remote code execution vulnerabilities.";

if(description)
{
  script_id(902563);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-31 10:37:30 +0200 (Wed, 31 Aug 2011)");
  script_cve_id("CVE-2011-2589", "CVE-2011-2590");
  script_bugtraq_id(48975);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("UUSee UUPlayer ActiveX Control Multiple Remote Code Execution Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/74216");
  script_xref(name : "URL" , value : "http://osvdb.org/74217");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44885");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68974");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68975");

  script_description(desc);
  script_summary("Check for the version of UUSee UUPlayer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
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
include("version_func.inc");
include("secpod_smb_func.inc");

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm Application
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\UUSEE";
if(!registry_key_exists(key:key)) {
  exit(0);
}

## Get Version
version = registry_get_sz(key:key, item:"DisplayVersion");
if(version)
{
  ## Check for UUSee UUPlayer 6.11.0609.2
  if(version_is_equal(version:version, test_version:"6.11.0609.2")) {
    security_hole(0);
  }
}
