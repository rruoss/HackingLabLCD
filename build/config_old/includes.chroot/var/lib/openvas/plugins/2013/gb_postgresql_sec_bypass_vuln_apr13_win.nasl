###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_sec_bypass_vuln_apr13_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# PostgreSQL Security Bypass Vulnerability - Apr13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to bypass security
  access to restricted backup files.
  Impact Level: Application";

tag_affected = "PostgreSQL version 9.2.x before 9.2.4 and 9.1.x before 9.1.9";
tag_insight = "Improper handling of a call for the pg_start_backup() or pg_stop_backup()
  functions.";
tag_solution = "Upgrade to PostgreSQL 9.1.8 or 9.2.3 or later,
  For updates refer to http://www.postgresql.org/download";
tag_summary = "This host is installed with PostgreSQL and is prone to security
  bypass vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803475";
CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1901");
  script_bugtraq_id(58878);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-09 17:48:56 +0530 (Tue, 09 Apr 2013)");
  script_name("PostgreSQL Security Bypass Vulnerability - Apr13 (Windows)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/91960");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52837");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1028387");
  script_xref(name : "URL" , value : "http://www.postgresql.org/about/news/1456");
  script_summary("Check for the vulnerable version of PostgreSQL on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("postgresql_detect.nasl","os_fingerprint.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_mandatory_keys("PostgreSQL/installed");
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

## Variable Initialization
pgsqlPort = "";
pgsqlVer = "";

## Exit if its not windows
if(host_runs("Windows") != "yes"){
  exit(0);
}

## Get the default port
pgsqlPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!pgsqlPort){
  pgsqlPort = 5432;
}

## Check the port status
if(!get_port_state(pgsqlPort)){
  exit(0);
}

## Get the PostgreSQL version
pgsqlVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:pgsqlPort);
if(isnull(pgsqlVer) ||  !(pgsqlVer =~ "^(9\.(1|2))")){
  exit(0);
}

## Check for vulnerable PostgreSQL versions
if(version_in_range(version:pgsqlVer, test_version:"9.1", test_version2:"9.1.8") ||
   version_in_range(version:pgsqlVer, test_version:"9.2", test_version2:"9.2.3"))
{
  security_warning(port:pgsqlPort);
  exit(0);
}
