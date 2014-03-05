###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mediawiki_mult_vuln_dec08.nasl 16 2013-10-27 13:09:52Z jan $
#
# MediaWiki Multiple Vulnerabilities Dec08
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright (c) 2008 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary codes in
  the context of the web application and execute cross site scripting attacks.";
tag_affected = "MediaWiki version 1.13.0 to 1.13.2
  MediaWiki version 1.12.x to 1.12.1
  MediaWiki versions prior to 1.6.11";
tag_insight = "The flaws are due to,
  - input is not properly sanitised before being returned to the user
  - input related to uploads is not properly sanitised before being used
  - SVG scripts are not properly sanitised before being used
  - the application allows users to perform certain actions via HTTP requests
    without performing any validity checks to verify the requests.";
tag_solution = "Upgrade to the latest versions 1.13.3, 1.12.2 or 1.6.11.
  http://www.mediawiki.org/wiki/Download";
tag_summary = "This host is running MediaWiki and is prone to Multiple
  Vulnerabilities.";

if(description)
{
  script_id(900421);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-29 13:55:43 +0100 (Mon, 29 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-5249", "CVE-2008-5250", "CVE-2008-5252");
  script_bugtraq_id(32844);
  script_name("MediaWiki Multiple Vulnerabilities Dec08");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33133");

  script_description(desc);
  script_summary("Check for the version of MediaWiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl");
  script_require_keys("MediaWiki/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!port){
  port = 80;
}

wikiVer = get_kb_item("MediaWiki/Version");
if(!wikiVer){
  exit(0);
}

if(version_in_range(version:wikiVer, test_version:"1.13.0", test_version2:"1.13.2") ||
   version_in_range(version:wikiVer, test_version:"1.12.0", test_version2:"1.12.1") ||
   version_is_less_equal(version:wikiVer, test_version:"1.6.10")){
  security_hole(port);
}
