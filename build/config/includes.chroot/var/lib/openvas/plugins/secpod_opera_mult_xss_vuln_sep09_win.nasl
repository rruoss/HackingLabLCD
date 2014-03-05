###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opera_mult_xss_vuln_sep09_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Opera Multiple Cross-Site Scripting Vulnerabilities - Sep09 (Win)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Attacker can exploit this issue to conduct XSS attacks to inject arbitrary web
  script or HTML.
  Impact Level: Application";
tag_affected = "Opera version 9.x and 10.x on Windows.";
tag_insight = "An error in the application which can be exploited to obtain complete control
  over feeds via a 'RSS' or 'Atom' feed. It is related to the rendering of the
  application/rss+xml content type as 'scripted content'.";
tag_solution = "No solution or patch is available as of 22nd September 2009, Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.opera.com/";
tag_summary = "This host is installed with Opera and is prone to multiple Cross-Site
  Scripting vulnerabilities.";

if(description)
{
  script_id(900857);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-23 08:37:26 +0200 (Wed, 23 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3265", "CVE-2009-3266");
  script_bugtraq_id(36418);
  script_name("Opera Multiple Cross-Site Scripting Vulnerabilities - Sep09 (Win)");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/506517/100/0/threaded");
  script_xref(name : "URL" , value : "http://securethoughts.com/2009/09/exploiting-chrome-and-operas-inbuilt-atomrss-reader-with-script-execution-and-more/");

  script_description(desc);
  script_summary("Check for the version of Opera");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_opera_detection_win_900036.nasl");
  script_require_keys("Opera/Win/Version");
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

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

# Check for Opera version 9.x and 10.x
if(operaVer =~ "^(9|10)\..*"){
  security_warning(0);
}
