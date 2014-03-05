###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_gis_line_string_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# MySQL 'Gis_line_string::init_from_wkb()'DOS Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation could allow users to cause a denial of service and
  to execute arbitrary code.
  Impact Level: Application";
tag_affected = "MySQL version 5.1 before 5.1.51";
tag_insight = "The flaw is due to an error in 'Gis_line_string::init_from_wkb()'
  function in 'sql/spatial.cc',allows remote authenticated users to cause a
  denial of service by calling the PolyFromWKB function with WKB data
  containing a crafted number of line strings or line points.";
tag_solution = "Upgrade to MySQL version 5.1.51
  For updates refer to http://dev.mysql.com/downloads";
tag_summary = "The host is running MySQL and is prone to denial of service
  vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801573";
CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)");
  script_cve_id("CVE-2010-3840");
  script_bugtraq_id(43676);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("MySQL 'Gis_line_string::init_from_wkb()' DOS Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42875");
  script_xref(name : "URL" , value : "http://bugs.mysql.com/bug.php?id=54568");
  script_xref(name : "URL" , value : "http://dev.mysql.com/doc/refman/5.1/en/news-5-1-51.html");

  script_description(desc);
  script_summary("Check for the version of MySQL");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
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
include("global_settings.inc");
include("host_details.inc");

## This nvt is prone to FP
if(report_paranoia < 2){
  exit(0);
}

sqlPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!sqlPort){
  sqlPort = 3306;
}

if(!get_port_state(sqlPort)){
  exit(0);
}

mysqlVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:sqlPort);
if(isnull(mysqlVer)){
  exit(0);
}

mysqlVer = eregmatch(pattern:"([0-9.a-z]+)", string:mysqlVer);
if(!isnull(mysqlVer[1]))
{
  if(version_in_range(version:mysqlVer[1], test_version:"5.1",test_version2:"5.1.50")){
    security_warning(sqlPort);
  }
}
