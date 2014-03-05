################################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediawiki_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# MediaWiki XSS Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to include arbitrary
  HTML or web scripts in the scope of the browser and allows to obtain
  sensitive information.

  Impact level: Application";

tag_affected = "MediaWiki version 1.14.0
  MediaWiki version 1.15.0";
tag_insight = "The flaw is due to the error in 'Special:Block' script in the
  'getContribsLink' function in 'SpecialBlockip.php' page. It fails to
  properly sanitize user-supplied input while processing the 'ip'
  parameter.";
tag_solution = "Apply the patch or Upgrade to MediaWiki version to 1.14.1, 1.15.1 or higher,
  http://download.wikimedia.org/mediawiki/1.14/mediawiki-1.14.1.patch.gz
  http://download.wikimedia.org/mediawiki/1.15/mediawiki-1.15.1.patch.gz
  http://download.wikimedia.org/mediawiki/1.14/mediawiki-1.14.1.tar.gz
  http://download.wikimedia.org/mediawiki/1.15/mediawiki-1.15.1.tar.gz";
tag_summary = "This host is running MediaWiki and is prone to XSS
  Vulnerability.";

if(description)
{
  script_id(800982);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-16 12:13:24 +0100 (Sat, 16 Jan 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-4589");
  script_bugtraq_id(35662);
  script_name("MediaWiki XSS Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35818");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51687");
  script_xref(name : "URL" , value : "http://lists.wikimedia.org/pipermail/mediawiki-announce/2009-July/000087.html");

  script_description(desc);
  script_summary("Check for the version of MediaWiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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


include("http_func.inc");
include("version_func.inc");

wikiPort = get_http_port(default:80);
if(!wikiPort){
  exit(0);
}

mediawiki = get_kb_item("MediaWiki/Version");
if(!mediawiki){
  exit(0);
}

if(mediawiki != NULL)
{
  ## Grep for affected MediaWiki Versions 1.14.0 and 1.15.0
  if(version_is_equal(version:mediawiki, test_version:"1.14.0") ||
     version_is_equal(version:mediawiki, test_version:"1.15.0")){
    security_warning(wikiPort);
    exit(0);
  }
}
