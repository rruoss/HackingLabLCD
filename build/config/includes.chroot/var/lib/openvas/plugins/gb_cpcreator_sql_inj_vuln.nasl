###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cpcreator_sql_inj_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# cP Creator 'tickets' Cookie SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi<santu@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to conduct SQL injection
  attacks.
  Impact Level: Application.";
tag_affected = "cP Creator Version 2.7.1 and prior.";
tag_insight = "Input passed to the 'tickets' cookie in index.php (if 'page' is set to
  'support' and 'task' is set to 'ticket') is not properly sanitised before
  being used in SQL queries.";
tag_solution = "No solution or patch is available as of 05th October, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.cpcreator.com/download.php";
tag_summary = "The host is running cP Creator and is prone to SQL Injection
  Vulnerability";

if(description)
{
  script_id(801006);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-06 07:21:15 +0200 (Tue, 06 Oct 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-3330");
  script_name("cP Creator 'tickets' Cookie SQL Injection Vulnerability");
  desc ="
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36815");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9726");

  script_description(desc);
  script_summary("Check for the version cP Creator");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_cpcreator_detect.nasl");
  script_family("Web application abuses");
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

cpcreatPort = get_http_port(default:80);
if(!cpcreatPort){
  exit(0);
}

cpcreatVer = get_kb_item("www/" + cpcreatPort + "/cPCreator");
if(!cpcreatVer){
  exit(0);
}

cpcreatVer = eregmatch(pattern:"^(.+) under (/.*)$", string:cpcreatVer);
if(cpcreatVer[1] != NULL)
{
  if(version_is_less_equal(version:cpcreatVer[1], test_version:"2.7.1")){
    security_hole(cpcreatPort);
  }
}
