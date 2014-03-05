###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_mult_vuln_jan13_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# PostgreSQL 'xml_parse()' And 'xslt_process()' Multiple Vulnerabilities (Win)
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
tag_impact = "Successful exploitation will allow attacker to modify data, obtain sensitive
  information or trigger outbound traffic to arbitrary external hosts.
  Impact Level: Application";

tag_affected = "PostgreSQL versions 8.3 before 8.3.20, 8.4 before 8.4.13,
  9.0 before 9.0.9, and 9.1 before 9.1.5 on Windows";
tag_insight = "- An error exists within the 'xml_parse()' function when parsing DTD data
    within XML documents.
  - An error exists within the 'xslt_process()' when parsing XSLT style sheets.";
tag_solution = "Upgrade to PostgreSQL 8.3.20, 8.4.13, 9.0.9 or 9.1.5 or later,
  For updates refer to http://www.postgresql.org/download/";
tag_summary = "This host is installed with PostgreSQL and is prone to multiple
  vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803219";
CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-3488", "CVE-2012-3489");
  script_bugtraq_id(55072, 55074);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-24 17:08:52 +0530 (Thu, 24 Jan 2013)");
  script_name("PostgreSQL 'xml_parse()' And 'xslt_process()' Multiple Vulnerabilities (Win)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/84804");
  script_xref(name : "URL" , value : "http://www.osvdb.org/84805");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50218");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027408");
  script_xref(name : "URL" , value : "http://www.postgresql.org/about/news/1407");
  script_xref(name : "URL" , value : "http://www.postgresql.org/support/security");

  script_description(desc);
  script_summary("Check for the version of PostgreSQL on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("postgresql_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_require_keys("PostgreSQL/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
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
if(isnull(pgsqlVer) ||  !(pgsqlVer =~ "^(8|9)")){
  exit(0);
}

## Check for vulnerable PostgreSQL versions
if(version_in_range(version:pgsqlVer, test_version:"8.3", test_version2:"8.3.19") ||
   version_in_range(version:pgsqlVer, test_version:"8.4", test_version2:"8.4.12") ||
   version_in_range(version:pgsqlVer, test_version:"9.0", test_version2:"9.0.8") ||
   version_in_range(version:pgsqlVer, test_version:"9.1", test_version2:"9.1.4")){
  security_hole(port:pgsqlPort);
}
