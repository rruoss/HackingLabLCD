##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mediawiki_xss_n_csrf_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# MediaWiki Cross-site Scripting (XSS) and Cross-site Request Forgery (CSRF) Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to inject arbitrary web
  script or HTML and to hijack the authentication of users.
  Impact Level: Application.";
tag_affected = "MediaWiki version 1.15 before 1.15.4 and 1.16 before 1.16 beta 3";

tag_insight = "- A flaw is present while processing crafted Cascading Style Sheets (CSS)
  strings, which are processed as scripts
  - An error is present in the 'Special:Userlogin' form, which allows remote
  attackers to hijack the authentication of users for requests that create
  accounts or reset passwords.";
tag_solution = "Upgrade to MediaWiki version 1.15.4 or 1.16 beta 3 or later
  For updates refer to http://dumps.wikimedia.org/mediawiki/";
tag_summary = "This host is running MediaWiki and is prone to Cross-site Scripting
  and Cross-Site Request Forgery vulnerabilities.";

if(description)
{
  script_id(902070);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-16 08:26:33 +0200 (Wed, 16 Jun 2010)");
  script_cve_id("CVE-2010-1647", "CVE-2010-1648");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("MediaWiki Cross-site Scripting (XSS) and Cross-site Request Forgery (CSRF) Vulnerabilities");
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


  script_description(desc);
  script_summary("Check for the version of MediaWiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_require_ports("Services/www", 80);
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl");
  script_require_keys("MediaWiki/Version"); 
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  script_xref(name : "URL" , value : "https://bugzilla.wikimedia.org/show_bug.cgi?id=23687");
  script_xref(name : "URL" , value : "https://bugzilla.wikimedia.org/show_bug.cgi?id=23371");
  script_xref(name : "URL" , value : "http://lists.wikimedia.org/pipermail/mediawiki-announce/2010-May/000091.html");
  exit(0);
}
		

include("http_func.inc");
include("version_func.inc");

mwPort = get_http_port(default:80);
if(!mwPort){
  exit(0);
}

mwVer = get_kb_item("MediaWiki/Version");
if(!mwVer){
  exit(0);
}

if(mwVer != NULL)
{
  ## Check for MediaWiki version < 1.15.4, 1.16 beta 3
  if(version_in_range(version:mwVer, test_version:"1.15.0", test_version2:"1.15.3") ||
     version_in_range(version:mwVer, test_version:"1.16.0", test_version2:"1.16.0.beta2")){
    security_hole(mwPort);
  }
}
