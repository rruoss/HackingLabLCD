###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_info_disc_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Mozilla Firefox Information Disclosure Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to obtain potentially
  sensitive information about heap memory addresses.
  Impact Level: Application";
tag_affected = "Mozilla Firefox version 3.6.16 and prior.";
tag_insight = "The flaw is due to an error in txXPathNodeUtils::getXSLTId function
  in txStandaloneXPathTreeWalker.cpp allows remote attackers to obtain
  potentially sensitive information about heap memory addresses via an XML
  document containing a call to the XSLT generate-id XPath function.";
tag_solution = "Upgrade to Mozilla Firefox version 4 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/new/";
tag_summary = "The host is installed with Mozilla Firefox and is prone to
  information disclosure vulnerability.";

if(description)
{
  script_id(801875);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_cve_id("CVE-2011-1712");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Mozilla Firefox Information Disclosure Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://scarybeastsecurity.blogspot.com/2011/03/multi-browser-heap-address-leak-in-xslt.html");

  script_description(desc);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_summary("Check the version of Mozilla Firefox");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver");
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

## Get Firefox version from KB
ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

## Check for Mozilla Firefox Versions
if(version_is_less_equal(version:ffVer, test_version:"3.6.16")){
  security_warning(0);
}
