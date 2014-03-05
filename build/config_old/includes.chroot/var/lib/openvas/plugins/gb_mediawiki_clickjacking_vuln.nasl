################################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediawiki_clickjacking_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# MediaWiki Frames Processing Clickjacking Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will let remote attackers to hijack the victim's
  click actions and possibly launch further attacks against the victim.

  Impact level: Application";

tag_affected = "MediaWiki version prior to 1.16.1";
tag_insight = "The flaw is caused by input validation errors when processing certain data
  via frames, which could allow clickjacking attacks.";
tag_solution = "Upgrade to MediaWiki 1.16.1 or later,
  For updates refer to http://www.mediawiki.org/wiki/Download";
tag_summary = "This host is running MediaWiki and clickjacking information disclosure
  vulnerability.";

if(description)
{
  script_id(801900);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_cve_id("CVE-2011-0003");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_name("MediaWiki Frames Processing Clickjacking Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/70272");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42810");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64476");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0017");
  script_xref(name : "URL" , value : "http://lists.wikimedia.org/pipermail/mediawiki-announce/2011-January/000093.html");

  script_description(desc);
  script_summary("Check for the version of MediaWiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl");
  script_require_ports("Services/www", 80);
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


include("http_func.inc");
include("version_func.inc");

wikiPort = get_http_port(default:80);
if(!wikiPort){
  exit(0);
}

mediawikiVer = get_kb_item("MediaWiki/Version");
if(!mediawikiVer){
  exit(0);
}

## Grep for affected MediaWiki Versions less than 1.16.1
if(version_is_less(version:mediawikiVer, test_version:"1.16.1")){
  security_hole(wikiPort);
}
