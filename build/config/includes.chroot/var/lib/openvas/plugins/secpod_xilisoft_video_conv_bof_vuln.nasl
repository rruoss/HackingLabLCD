###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xilisoft_video_conv_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Xilisoft Video Converter Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "This issue can be exploited to corrupt the memory and to execute arbitrary
  code in the context of the affected application.
  Impact Level: Application";
tag_affected = "Xilisoft Video Converter version 3.x to 3.1.53.0704n and 5.x to 5.1.23.0402
  on Windows.";
tag_insight = "The cause is due to an error in ape_plugin.plg when parsing malicious .CUE
  files containing overly long string.";
tag_solution = "No solution or patch is available as of 27th April, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.xilisoft.com/";
tag_summary = "This host is with installed Xilisoft Video Converter and is prone
  to Buffer Overflow Vulnerability.";

if(description)
{
  script_id(900630);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-28 07:58:48 +0200 (Tue, 28 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1370");
  script_bugtraq_id(34472);
  script_name("Xilisoft Video Converter Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34660");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8452");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49807");

  script_description(desc);
  script_summary("Check for the version of Xilisoft Video Converter");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_xilisoft_video_conv_detect.nasl");
  script_require_keys("Xilisoft/Video/Conv/Ver");
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

xsoftVer = get_kb_item("Xilisoft/Video/Conv/Ver");
if(!xsoftVer){
  exit(0);
}

if(version_in_range(version:xsoftVer, test_version:"3.0", test_version2:"3.1.53.0704n") ||
   version_in_range(version:xsoftVer, test_version:"5.0", test_version2:"5.1.23.0402")){
  security_hole(0);
}
