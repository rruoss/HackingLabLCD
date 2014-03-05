###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phorum_xss_n_csrf_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Phorum Cross-Site Scripting and Cross-site request forgery Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code in
  the context of an application.
  Impact Level: Application";
tag_affected = "Phorum version prior to 5.2.16";
tag_insight = "The flaws are due to unspecified errors in the application.";
tag_solution = "Upgrade Phorum to 5.2.16 or later,
  For updates refer to http://www.phorum.org/downloads.php";
tag_summary = "This host is running Phorum and is prone to cross-site scripting
  and cross-site request forgery vulnerabilities.";

if(description)
{
  script_id(802160);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_cve_id("CVE-2011-3381", "CVE-2011-3382");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Phorum Cross-Site Scripting and Cross-site request forgery Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN71435255/index.html");
  script_xref(name : "URL" , value : "http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000068.html");

  script_description(desc);
  script_summary("Check version of Phorum");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phorum_detect.nasl");
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

## Get HTTP Port
phorumPort = get_http_port(default:80);
if(!phorumPort){
  exit(0);
}

## Get version from kb
phorumVer =  get_version_from_kb(port:phorumPort,app:"phorum");
if(!phorumVer){
  exit(0);
}

# Check for Phorum Version < 5.2.16
if(version_is_less(version:phorumVer, test_version:"5.2.16")){
  security_hole(phorumPort);
}
