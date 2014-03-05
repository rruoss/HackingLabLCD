###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dokuwiki_mult_csrf_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# DokuWiki Multiple Cross Site Request Forgery Vulnerabilities
#
# Authors:
# Rachana Shetty <srachan@secpod.com>
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
tag_impact = "Successful exploitation allows attackers to conduct cross site request
  forgery attacks via unknown vectors.
  Impact Level: Application.";
tag_affected = "Dokuwiki versions prior to 2009-12-25c";
tag_insight = "The flaws are due to error in 'ACL' Manager plugin (plugins/acl/ajax.php) that
  allows users to perform certain actions via HTTP requests without performing
  any validity checks.";
tag_solution = "Update to version 2009-12-25c or later.
  For updates refer to http://www.splitbrain.org/go/dokuwiki";
tag_summary = "This host is installed with Dokuwiki and is prone to multiple Cross
  Site Scripting vulnerabilities.";

if(description)
{
  script_id(800989);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-19 11:58:13 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2010-0289");
  script_name("DokuWiki Multiple Cross Site Request Forgery Vulnerabilities");
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
  script_summary("Check for the version of DokuWiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38205");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0150");
  script_xref(name : "URL" , value : "http://bugs.splitbrain.org/index.php?do=details&amp;task_id=1853");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

dokuwikiPort = get_http_port(default:80);
if(!dokuwikiPort){
  exit(0);
}

# check Version from KB
dokuVer = get_kb_item("www/" + dokuwikiPort + "/DokuWiki");
if(isnull(dokuVer)){
  exit(0);
}

dokuVer = eregmatch(pattern:"^(.+) under (/.*)$", string:dokuVer);
if(dokuVer[1] != NULL)
{
  # Check for version less then 2009-12-25c
  if(version_is_less(version:dokuVer[1], test_version:"2009.12.25c")){
    security_hole(dokuwikiPort);
  }
}
