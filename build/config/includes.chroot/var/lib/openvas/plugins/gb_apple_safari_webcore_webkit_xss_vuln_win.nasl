###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_webcore_webkit_xss_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Apple Safari Webcore Webkit 'XSSAuditor.cpp' XSS Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to bypass a cross-site scripting
  (XSS) protection mechanism via a crafted string.
  Impact Level: Application";
tag_affected = "Apple Safari version 5.1.7 on Windows";
tag_insight = "The flaw is due to 'html/parser/XSSAuditor.cpp' in WebCore in WebKit does not
  consider all possible output contexts of reflected data.";
tag_solution = "No solution or patch is available as of 21st November, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.apple.com/safari/download/";
tag_summary = "This host is installed with Apple Safari and is prone to cross site
  scripting vulnerability.";

if(description)
{
  script_id(802499);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-5851");
  script_bugtraq_id(56570);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-21 15:41:09 +0530 (Wed, 21 Nov 2012)");
  script_name("Apple Safari Webcore Webkit 'XSSAuditor.cpp' XSS Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "https://bugs.webkit.org/show_bug.cgi?id=92692");
  script_xref(name : "URL" , value : "http://blog.opensecurityresearch.com/2012/09/simple-cross-site-scripting-vector-that.html");

  script_description(desc);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_summary("Check the version of Apple Safari on Windows");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_require_keys("AppleSafari/Version");
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

# Variable Initialization
safVer = NULL;

## Get the OS name
safVer = get_kb_item("AppleSafari/Version");
if(!safVer){
  exit(0);
}
## Check for Apple Safari Versions 5.1.7 (5.34.57.2)
if(version_is_equal(version:safVer, test_version:"5.34.57.2")){
  security_warning(0);
}
