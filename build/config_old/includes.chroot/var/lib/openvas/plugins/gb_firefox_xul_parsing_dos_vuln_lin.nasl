###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_xul_parsing_dos_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Firefox XUL Parsing Denial of Service Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to cause the browser to crash.
  Impact Level: Application";
tag_affected = "Firefox version 3.0 to 3.0.8 on Linux.";
tag_insight = "Error in browser due to improper parsing of XUL (XML) documents while opening
  a specially-crafted XML document containing long series of start-tags with no
  corresponding end-tags.";
tag_solution = "Upgrade to Firefox version 3.6.3 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/firefox.html";
tag_summary = "The host is installed with Mozilla Firefox browser and is prone to
  XUL Parsing Vulnerability.";

if(description)
{
  script_id(800390);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-1232");
  script_name("Firefox XUL Parsing Denial of Service Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8306");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49521");

  script_description(desc);
  script_summary("Check for the version of Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_require_keys("Firefox/Linux/Ver");
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

ffVer = get_kb_item("Firefox/Linux/Ver");
if(!ffVer){
  exit(0);
}

# Grep for firefox version 3.0 to 3.0.8
if(version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.0.8")){
  security_warning(0);
}
