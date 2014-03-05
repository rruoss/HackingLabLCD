###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_info_disc_vuln_macosx.nasl 13 2013-10-27 12:16:33Z jan $
#
# Opera Multiple Information Disclosure Vulnerabilities (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to gain sensitive
  information about visited web pages by calling getComputedStyle method or
  via a crafted HTML document.
  Impact Level: Application";
tag_affected = "Opera version 10.50 on Mac OS X";
tag_insight = "Multiple flaws are due to an implementation erros in,
  - The JavaScript failing to restrict the set of values contained in the
    object returned by the getComputedStyle method.
  - The Cascading Style Sheets (CSS) failing to handle the visited
    pseudo-class.";
tag_solution = "No solution or patch is available as of 09th December, 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.opera.com/download/";
tag_summary = "The host is installed with Opera and is prone to multiple
  information disclosure vulnerabilities.";

if(description)
{
  script_id(802364);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2010-5072", "CVE-2010-5068");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-09 16:10:28 +0530 (Fri, 09 Dec 2011)");
  script_name("Opera Multiple Information Disclosure Vulnerabilities (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://w2spconf.com/2010/papers/p26.pdf");
  script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2010-5068");
  script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2010-5072");

  script_description(desc);
  script_summary("Check for the version of Opera on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
   script_dependencies("gb_opera_detect_macosx.nasl");
  script_require_keys("Opera/MacOSX/Version");
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

operaVer = get_kb_item("Opera/MacOSX/Version");
if(!operaVer){
  exit(0);
}

# Check for opera version is equal to 10.50
if(version_is_equal(version:operaVer, test_version:"10.50")){
  security_warning(0);
}
