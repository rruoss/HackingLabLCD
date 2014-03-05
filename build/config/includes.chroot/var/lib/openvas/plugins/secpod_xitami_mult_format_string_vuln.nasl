###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xitami_mult_format_string_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Xitami Multiple Format String Vulnerabilities
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  and can lead to application crash.
  Impact Level: Application";
tag_affected = "Xitami version 2.5c2 and prior.";
tag_insight = "- Error exists while handling a format string specifiers in a Long Running
    Web Process (LRWP) request, which triggers incorrect logging code involving
    the sendfmt function in the SMT kernel.
  - Error in Server Side Includes (SSI) filter when processes requests with
    specially crafted URIs ending in .ssi, .shtm, or .shtml, which triggers
    incorrect logging code involving the sendfmt function in the SMT kernel.";
tag_solution = "No solution or patch is available as of 05th May, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.xitami.com/";
tag_summary = "This host has Xitami web server installed and is prone to
  Multiple Format String Vulnerabilities.";

if(description)
{
  script_id(900548);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-06 08:04:28 +0200 (Wed, 06 May 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-6519", "CVE-2008-6520");
  script_bugtraq_id(28603);
  script_name("Xitami Multiple Format String Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/5354");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/41644");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/41645");

  script_description(desc);
  script_summary("Check for the version of Xitami Web Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_xitami_server_detect.nasl");
  script_require_keys("Xitami/Ver");
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

xVer = get_kb_item("Xitami/Ver");
if(xVer == NULL){
  exit(0);
}

if(version_is_less_equal(version:xVer, test_version:"2.5.c2")){
  security_hole(0);
}
