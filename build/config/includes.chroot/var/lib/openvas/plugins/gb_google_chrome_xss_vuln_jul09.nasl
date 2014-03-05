###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_xss_vuln_jul09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Google Chrome Cross-Site Scripting Vulnerability - July09
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
tag_impact = "Successful exploitation will allow remote attackers to conduct Cross-Site
  Scripting attacks via vectors related to injecting a Refresh header or
  specifying the content of a Refresh header.
  Impact Level: Application";
tag_affected = "Google Chrome version 1.0.154.48 and prior.";
tag_insight = "Error exists when application fails to block 'javascript:' URIs in Refresh
  headers in HTTP responses.";
tag_solution = "No solution or patch is available as of 08th July, 2009. Information regarding
  this issue will be updated once the solution details are available.
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host has Google Chrome installed and is prone to Cross-Site
  Scripting vulnerability.";

if(description)
{
  script_id(800828);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-09 10:58:23 +0200 (Thu, 09 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2352");
  script_bugtraq_id(35572);
  script_name("Google Chrome Cross-Site Scripting Vulnerability - July09");
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
  script_xref(name : "URL" , value : "http://websecurity.com.ua/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/504723/100/0/threaded");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/504718/100/0/threaded");

  script_description(desc);
  script_summary("Check for the Version of Google Chrome");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_require_keys("GoogleChrome/Win/Ver");
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

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

# Check for Google Chrome version <= 1.0.154.48
if(version_is_less_equal(version:chromeVer, test_version:"1.0.154.48")){
  security_warning(0);
}
