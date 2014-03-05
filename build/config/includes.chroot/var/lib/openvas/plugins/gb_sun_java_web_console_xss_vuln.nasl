###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_web_console_xss_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Sun Java Web Console Multiple XSS Vulnerabilities
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
tag_impact = "Successful exploitation will let the remote attacker to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected site.
  Impact Level: Application";
tag_affected = "Sun Java Web Console version 3.0.2 to 3.0.5";
tag_insight = "Errors in help jsp script that is not properly sanitising input data before
  being returned to the user, which can be exploited to cause web script or
  HTML code injection.";
tag_solution = "Apply patch from below link,
  http://sunsolve.sun.com/search/document.do?assetkey=1-66-262428-1";
tag_summary = "The host is running Java Web Console and is prone to Multiple
  Cross-Site Scripting Vulnerabilities.";

if(description)
{
  script_id(800826);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-09 10:58:23 +0200 (Thu, 09 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2283");
  script_name("Sun Java Web Console Multiple XSS Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35597");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1712");
  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-21-136987-03-1");

  script_description(desc);
  script_summary("Check for the Version of Java Web Console");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sun_java_web_console_detect.nasl");
  script_require_keys("Sun/JavaWebConsole/Ver");
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

jwcPort = 6789;
jwcVer = get_kb_item("Sun/JavaWebConsole/Ver");

if(jwcVer != NULL)
{
  # Check for Version 3.0.2 <= 3.0.5
  if(version_in_range(version:jwcVer, test_version:"3.0.2",
                                      test_version2:"3.0.5")){
    security_warning(jwcPort);
  }
}
