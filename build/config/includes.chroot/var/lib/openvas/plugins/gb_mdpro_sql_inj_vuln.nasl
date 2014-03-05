###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mdpro_sql_inj_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# MDPro Surveys Module SQL Injection Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "This flaw can be exploited via malicious SQL commands to modify or delete
  information in the back-end database.
  Impact Level: Application";
tag_affected = "MDPro version 1.083.x";
tag_insight = "The Surveys module fails to validate the user supplied data passed into
  the 'pollID' parameter before using it in an SQL query.";
tag_solution = "No solution or patch is available as of 06th August, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.maxdev.com/";
tag_summary = "This host is installed with MDPro and is prone to SQL Injection
  vulnerability.";

if(description)
{
  script_id(800919);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-07 07:29:21 +0200 (Fri, 07 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2618");
  script_bugtraq_id(35495);
  script_name("MDPro Surveys Module SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9021");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51385");

  script_description(desc);
  script_summary("Check for the version of MDPro");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mdpro_detect.nasl");
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

mdproPort = get_http_port(default:80);
if(!mdproPort){
  exit(0);
}

mdproVer = get_kb_item("www/" + mdproPort + "/MDPro");
mdproVer = eregmatch(pattern:"^(.+) under (/.*)$", string:mdproVer);

if(mdproVer[1] =~ "^1\.083"){
  security_hole(mdproPort);
}
