###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_jdbc_driver_sql_inj_vuln_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# PostgreSQL JDBC Driver SQL Injection Vulnerability (Win)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow attackers to manipulate SQL queries by
  injecting arbitrary SQL code and gain sensitive information.
  Impact Level: Application";

tag_affected = "PostgreSQL JDBC Driver versions 8.1 on Windows";
tag_insight = "An error exists within the JDBC driver which fails to escape unspecified
  JDBC statement parameters.";
tag_solution = "Upgrade to PostgreSQL JDBC Driver versions 8.2 or later,
  For updates refer to http://jdbc.postgresql.org/download.html";
tag_summary = "This host is installed with PostgreSQL with JDBC Driver and is
  prone to sql injection vulnerability.";

if(description)
{
  script_id(803220);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-1618");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-24 19:16:05 +0530 (Thu, 24 Jan 2013)");
  script_name("PostgreSQL JDBC Driver SQL Injection Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/80641");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Mar/125");
  script_xref(name : "URL" , value : "https://bugzilla.novell.com/show_bug.cgi?id=754273");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2012-03/0126.html");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/111239/PostgreSQL-JDBC-Driver-8.1-SQL-Injection.html");

  script_description(desc);
  script_summary("Check for the version of PostgreSQL JDBC Driver on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_postgresql_detect_win.nasl");
  script_require_keys("PostgreSQL/Win/Ver");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
pgsqlVer = "";
pgkey = "";
pgjdbcVer = "";

## Get PostgreSQL version from KB
pgsqlVer = get_kb_item("PostgreSQL/Win/Ver");
if(!pgsqlVer || !(pgsqlVer =~ "^9.1")) exit(0);

## Get PostgreSQL JDBC Driver version from Registry
pgkey = "SOFTWARE\EnterpriseDB\pgJDBC";
if(!registry_key_exists(key:pgkey)){
  exit(0);
}

# Get version from Version key
pgjdbcVer = registry_get_sz(key:pgkey, item:"Version");
if(pgjdbcVer && pgjdbcVer =~ "^8.1"){
  security_hole(0);
}
