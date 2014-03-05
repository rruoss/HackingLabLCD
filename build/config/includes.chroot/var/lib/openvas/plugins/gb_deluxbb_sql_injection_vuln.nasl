###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_deluxbb_sql_injection_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# DeluxeBB 'newpost.php' SQL Injection Vulnerability
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary SQL
  commands via the membercookie cookie when adding a new thread.
  Impact Level: Application.";
tag_affected = "DeluxeBB version 1.3 and prior.";
tag_insight = "The flaw is due to error in 'newpost.php', which is not properly
  sanitizing user supplied input data.";
tag_solution = "No solution or patch is available as of 14th May, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.deluxebb.com/index.php?content=downloads";
tag_summary = "The host is running DeluxeBB and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_id(801334);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2010-1859");
  script_bugtraq_id(39962);
  script_name("DeluxeBB 'newpost.php' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2010-1859");
  script_xref(name : "URL" , value : "http://php-security.org/2010/05/06/mops-2010-011-deluxebb-newthread-sql-injection-vulnerability/index.html");

  script_description(desc);
  script_summary("Check for the version of DeluxeBB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_dependencies("deluxeBB_detect.nasl");
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

dbbPort = get_http_port(default:80);
if(!dbbPort){
  exit(0);
}

if(vers = get_version_from_kb(port:dbbPort,app:"deluxeBB")) 
{
  if(version_is_less_equal(version:vers, test_version:"1.3")){
    security_hole(port:dbbPort);
  }
}
