###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_https_sessions_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft Explorer HTTPS Sessions Multiple Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation allows remote attackers to overwrite or delete
  arbitrary cookies via a Set-Cookie header in an HTTP response, which results
  into cross site scripting, cross site request forgery and denial of service
  attacks.
  Impact Level: Application";
tag_affected = "Microsoft Explorer versions 7, 8 and 9";
tag_insight = "Multiple flaws are due to not properly restricting modifications to
  cookies established in HTTPS sessions.";
tag_solution = "No solution or patch is available as of 17th August, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/windows/internet-explorer/default.aspx";
tag_summary = "The host is installed with Microsoft Explorer and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(802140);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_cve_id("CVE-2008-7295");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Microsoft Explorer HTTPS Sessions Multiple Vulnerabilities (Windows)");
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
  script_xref(name : "URL" , value : "http://scarybeastsecurity.blogspot.com/2008/11/cookie-forcing.html");
  script_xref(name : "URL" , value : "http://code.google.com/p/browsersec/wiki/Part2#Same-origin_policy_for_cookies");

  script_description(desc);
  script_summary("Check for the version of Microsoft Explorer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
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

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# Check for MS IE version 7.x, 8.x and 9.x
if(version_in_range(version:ieVer, test_version:"7.0.5000.00000", test_version2:"7.0.6001.16659") ||
   version_in_range(version:ieVer, test_version:"8.0.6000.00000", test_version2:"8.0.6001.18702") ||
   version_in_range(version:ieVer, test_version:"9.0.7000.00000", test_version2:"9.0.8112.16421")){
  security_hole(0);
}
