###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_mult_format_string_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# MySQL 'sql_parse.cc' Multiple Format String Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation could allow remote authenticated users to cause a Denial
  of Service and possibly have unspecified other attacks.
  Impact Level: Application";
tag_affected = "MySQL version 4.0.0 to 5.0.83 on all running platform.";
tag_insight = "The flaws are due to error in the 'dispatch_command' function in sql_parse.cc
  in libmysqld/ which can caused via format string specifiers in a database name
  in a 'COM_CREATE_DB' or 'COM_DROP_DB' request.";
tag_solution = "Upgrade to MySQL version 5.1.36 or later
  http://dev.mysql.com/downloads";
tag_summary = "The host is running MySQL and is prone to Multiple Format String
  vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800842";
CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-17 12:47:28 +0200 (Fri, 17 Jul 2009)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-2446");
  script_bugtraq_id(35609);
  script_name("MySQL 'sql_parse.cc' Multiple Format String Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/55734");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35767");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51614");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/504799/100/0/threaded");

  script_description(desc);
  script_summary("Check for the Version of MySQL");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_require_keys("MySQL/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("misc_func.inc");
include("version_func.inc");
include("host_details.inc");


sqlPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!sqlPort){
  sqlPort = 3306;
}

if(!get_port_state(sqlPort)){
  exit(0);
}

mysqlVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:sqlPort);
if(mysqlVer != NULL)
{
  if(version_in_range(version:mysqlVer, test_version:"4.0",
                                        test_version2:"5.0.83")){
    security_hole(sqlPort);
  }
}
