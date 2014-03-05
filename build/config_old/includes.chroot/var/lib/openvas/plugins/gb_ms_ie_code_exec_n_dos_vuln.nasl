###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_code_exec_n_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft Internet Explorer Code Execution and DoS Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code
  or cause denial of service.
  Impact Level: System/Application";
tag_affected = "Microsoft Internet Explorer versions 6 through 9 and 10 Consumer Preview";
tag_insight = "The flaws are due to memory corruptions, and buffer overflow errors.";
tag_solution = "No solution or patch is available as of 15th March, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/windows/internet-explorer/default.aspx";
tag_summary = "The host is installed with Microsoft Internet Explorer and is
  prone to arbitrary code execution and denial of service vulnerabilities.";

if(description)
{
  script_id(802708);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1544", "CVE-2012-1545");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-15 11:06:57 +0530 (Thu, 15 Mar 2012)");
  script_name("Microsoft Internet Explorer Code Execution and DoS Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.zdnet.com/blog/security/pwn2own-2012-ie-9-hacked-with-two-0day-vulnerabilities/10621");
  script_xref(name : "URL" , value : "http://arstechnica.com/business/news/2012/03/ie-9-on-latest-windows-gets-stomped-at-hacker-contest.ars");

  script_description(desc);
  script_summary("Check for the version of Microsoft Internet Explorer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

# Check for MS IE version 6.x, 7.x, 8.x and 9.x
if(version_is_equal(version:ieVer, test_version:"10.0.8250.0") ||
   version_in_range(version:ieVer, test_version:"6.0", test_version2:"6.0.3790.3959") ||
   version_in_range(version:ieVer, test_version:"7.0", test_version2:"7.0.6001.16659") ||
   version_in_range(version:ieVer, test_version:"8.0", test_version2:"8.0.6001.18702") ||
   version_in_range(version:ieVer, test_version:"9.0", test_version2:"9.0.8112.16421")){
  security_hole(0);
}
