##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mediawiki_mult_xss_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# MediaWiki Multiple XSS Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker include arbitrary HTML or web
  scripts in the scope of the browser. This may lead to cross site scripting
  attacks and the attacker may gain sensitive information of the remote user
  or of the web application.

  Impact level: Application";

tag_affected = "MediaWiki version prior to 1.13.4
  MediaWiki version prior to 1.12.4
  MediaWiki version prior to 1.6.12";
tag_insight = "Multiple flaws are caused as the data supplied by the user via unspecified
  vectors is not adequately sanitised before being passed into the file
  'config/index.php' of MediaWiki.";
tag_solution = "Apply the security updates accordingly.
  MediaWiki Version 1.13.4
  MediaWiki Version 1.12.4
  MediaWiki Version 1.6.12";
tag_summary = "This host is running MediaWiki and is prone to Multiple XSS
  Vulnerabilities.";

if(description)
{
  script_id(900469);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_bugtraq_id(33681);
  script_cve_id("CVE-2009-0737");
  script_name("MediaWiki Multiple XSS Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33881");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/0368");

  script_description(desc);
  script_summary("Check for the version of MediaWiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("secpod_mediawiki_detect.nasl");
  script_require_keys("MediaWiki/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");

wikiPort = get_kb_item("Services/www");
if(!get_port_state(wikiPort)){
  exit(0);
}

mediawiki = get_kb_item("MediaWiki/Version");
if(!mediawiki){
  exit(0);
}

if(mediawiki != NULL)
{
  # Grep for affected MediaWiki Versions
  if(version_in_range(version:mediawiki, test_version:"1.13", test_version2:"1.13.3") ||
     version_in_range(version:mediawiki, test_version:"1.12", test_version2:"1.12.3") ||
     version_in_range(version:mediawiki, test_version:"1.6", test_version2:"1.6.11")){
    security_warning(wikiPort);
    exit(0);
  }
}
