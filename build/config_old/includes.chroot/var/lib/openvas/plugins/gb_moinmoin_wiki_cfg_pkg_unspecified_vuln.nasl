###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moinmoin_wiki_cfg_pkg_unspecified_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# MoinMoin Wiki 'cfg' Package Configuration Unspecified Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
tag_impact = "Impack is currently unknown.
  Impact Level: Application";
tag_affected = "MoinMoin Wiki version before 1.8.7 on all platforms.";
tag_insight = "The flaw is due to default configuration of 'cfg' package which does not
  prevent unsafe package actions causing unspecified impact.";
tag_solution = "Upgrade to MoinMoin Wiki 1.8.7 or later
  For updates refer to http://moinmo.in/MoinMoinDownload";
tag_summary = "This host is running MoinMoin Wiki and is prone to unspecified
  vulnerabilities.";

if(description)
{
  script_id(800174);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2010-0717");
  script_name("MoinMoin Wiki 'cfg' Package Configuration Unspecified Vulnerability");
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
  script_xref(name : "URL" , value : "http://moinmo.in/MoinMoinRelease1.8");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/02/15/2");
  script_xref(name : "URL" , value : "http://moinmo.in/SecurityFixes/AdvisoryForDistributors");

  script_description(desc);
  script_summary("Check for the version of MoinMoin Wiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
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

## Get the port where MoinMoin Wiki application is running
moinWikiPort = get_http_port(default:80);
if(!moinWikiPort){
  exit(0);
}

## Get MoinMoin Wiki Version from KB
moinWikiVer = get_kb_item("www/" + moinWikiPort + "/moinmoinWiki");
moinWikiVer = eregmatch(pattern:"^(.+) under (/.*)$", string:moinWikiVer);

if(moinWikiVer[1] != NULL)
{
  ## Check for version before 1.8.7
  if(version_is_less(version:moinWikiVer[1], test_version:"1.8.7")){
    security_hole(moinWikiPort);
  }
}
