##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_postgresql_dos_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# PostgreSQL Denial of Service Vulnerability (Linux)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let the attacker cause stack consumption or
  denial of service through mismatched encoding conversion requests.";
tag_affected = "PostgreSQL versions before 8.3.7, 8.2.13, 8.1.17, 8.0.21, and 7.4.25";
tag_insight = "This flaw is due to failure in converting a localized error message to the
  client-specified encoding.";
tag_solution = "Upgrade to respective version below,
  PostgreSQL 8.3.7 or 8.2.13 or 8.1.17 or 8.0.21 or 7.4.25
  http://www.postgresql.org";
tag_summary = "This host is installed with PostgreSQL Server and is prone to
  denial of service vulnerabilities.";

if(description)
{
  script_id(900480);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-0922");
  script_bugtraq_id(34090);
  script_name("PostgreSQL Denial of Service Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=488156");
  script_xref(name : "URL" , value : "http://archives.postgresql.org/pgsql-bugs/2009-02/msg00172.php");

  script_description(desc);
  script_summary("Check for the version of PostgreSQL");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_postgresql_detect_lin.nasl", "find_service.nasl");
  script_require_ports("Services/postgres", 5432);
  script_require_keys("PostgreSQL/Lin/Ver");
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

gresqlport = get_kb_item("Services/postgres");
if(!gresqlport){
  gresqlport = 5432;
}

pgsqlVer = get_kb_item("PostgreSQL/Lin/Ver");
if(!pgsqlVer){
  exit(0);
}

# Grep for PostgreSQL versions before 8.3.7, 8.2.13, 8.1.17, 8.0.21, and 7.4.25
if(version_in_range(version:pgsqlVer, test_version:"8.3", test_version2:"8.3.6")  ||
   version_in_range(version:pgsqlVer, test_version:"8.2", test_version2:"8.2.12") ||
   version_in_range(version:pgsqlVer, test_version:"8.1", test_version2:"8.1.16") ||
   version_in_range(version:pgsqlVer, test_version:"8.0", test_version2:"8.0.20") ||
   version_in_range(version:pgsqlVer, test_version:"7.4", test_version2:"7.4.24")){
  security_warning(gresqlport);
}
