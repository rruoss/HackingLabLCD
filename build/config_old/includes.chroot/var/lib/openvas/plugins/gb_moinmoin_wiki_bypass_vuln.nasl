###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moinmoin_wiki_bypass_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# MoinMoin Wiki Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to bypass intended access
  restrictions by requesting an item.
  Impact Level: Application";
tag_affected = "MoinMoin Wiki version 1.7.1 and prior";
tag_insight = "The flaw is exists due to an error in handling of 'textcha' protection mechanism,
  which can be bypassed by modifying the 'textcha-question' and 'textcha-answer fields'
  to have empty values.";
tag_solution = "Upgrade MoinMoin Wiki 1.7.1-3 or latest,
  For updates refer to http://moinmo.in/MoinMoinDownload";
tag_summary = "This host is running MoinMoin Wiki and is prone to security bypass
  vulnerability.";

if(description)
{
  script_id(801306);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2010-1238");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("MoinMoin Wiki Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/");
  script_xref(name : "URL" , value : "http://www.debian.org/security/2010/dsa-2024");
  script_xref(name : "URL" , value : "http://comments.gmane.org/gmane.comp.security.oss.general/2773");

  script_description(desc);
  script_summary("Check for the version of MoinMoin Wiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moinmoin_wiki_detect.nasl");
  script_require_ports("Services/www", 80);
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

moinWikiPort = get_http_port(default:80);
if(!moinWikiPort){
  exit(0);
}

## Get MoinMoin Wiki Version from KB
moinWikiVer = get_kb_item("www/" + moinWikiPort + "/moinmoinWiki");
moinWikiVer = eregmatch(pattern:"^(.+) under (/.*)$", string:moinWikiVer);

if(moinWikiVer[1] != NULL)
{
  ## Check for version 1.7.1
  if(version_is_less_equal(version:moinWikiVer[1], test_version:"1.7.1")){
    security_warning(moinWikiPort);
  }
}
