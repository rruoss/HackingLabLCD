###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_crawltrack_unspecified_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# CrawlTrack Unspecified Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary PHP
  code with the privileges of the web server.
  Impact Level: Application";
tag_affected = "CrawlTrack versions before 3.2.7";
tag_insight = "The flaw is caused by input validation errors in the stats pages when
  processing user-supplied data and parameters, which could allow remote
  attackers to execute arbitrary PHP code with the privileges of the web
  server.";
tag_solution = "Upgrade to CrawlTrack version 3.2.7 or later,
  For updates refer to http://www.crawltrack.net/download.php";
tag_summary = "The host is running CrawlTrack and is prone to unspecified
  vulnerability.";

if(description)
{
  script_id(901179);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-05 04:12:38 +0100 (Sat, 05 Feb 2011)");
  script_cve_id("CVE-2010-4537");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("CrawlTrack Unspecified Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.crawltrack.net/changelog.php");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/3342");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2011/01/03/7");

  script_description(desc);
  script_summary("Check for the version of CrawlTrack");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_crawltrack_detect.nasl");
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

## Get Http Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check for CrawlTrack version prior to 3.2.7
if(ver = get_version_from_kb(port:port,app:"CrawlTrack"))
{
  if(version_is_less(version: ver, test_version: "3.2.7")){
    security_hole(port:port);
  }
}
