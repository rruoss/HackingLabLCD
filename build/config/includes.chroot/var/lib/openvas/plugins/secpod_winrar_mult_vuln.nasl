###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_winrar_mult_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# WinRAR Multiple Unspecified Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to cause heap corruptions
  or stack-based buffer overflows or execution of arbitrary code.
  Impact Level: Application";
tag_affected = "WinRAR versions prior to 3.71";
tag_insight = "The flaw is due to unspecified errors in the processing of several
  archive files.";
tag_solution = "Upgrade to WinRAR version 3.71 or later.
  For updates refer to http://www.rarlab.com/download.htm";
tag_summary = "This host has WinRAR installed and is prone to Multiple
  Vulnerability.";

if(description)
{
  script_id(901022);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-7144");
  script_name("WinRAR Multiple Unspecified Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/29407");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/41251");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2008/0916/references");

  script_description(desc);
  script_summary("Checks for the version of WinRAR");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_winrar_detect.nasl");
  script_require_keys("WinRAR/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

winrarVer = get_kb_item("WinRAR/Ver");
if(winrarVer != NULL)
{
  # Check for version WinRAR < 3.71 
  if(version_is_less(version:winrarVer, test_version:"3.71")){
     security_hole(0);
   }
}
