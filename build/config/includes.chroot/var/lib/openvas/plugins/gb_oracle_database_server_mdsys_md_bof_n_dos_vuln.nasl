###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_database_server_mdsys_md_bof_n_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Oracle Database Server MDSYS.MD Buffer Overflows and Denial of Service Vulnerabilities
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
tag_impact = "Successful exploitation allows an attacker to execute arbitrary code. It
  can also be exploited to cause denial of service by killing Oracle server
  process.
  Impact Level: Application";
tag_affected = "Oracle Database server versions 8.1.7.4, 9.0.1.5, 9.2.0.7, and 10.1.0.4";
tag_insight = "The flaws are due to error in 'MDSYS.MD' package that is used in the
  Oracle spatial component. The package has EXECUTE permission to PUBLIC, so
  any Oracle database user can exploit the vulnerability to execute arbitrary
  code.";
tag_solution = "Apply patches from below link,
  http://www.oracle.com/technetwork/topics/security/cpujan2007-101493.html";
tag_summary = "This host is running Oracle database and is prone to buffer
  overflow and denial of service vulnerabilities.";

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

if(description)
{
  script_xref(name : "URL" , value : "http://osvdb.org/32911");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1017522");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/31541");
  script_xref(name : "URL" , value : "http://www.us-cert.gov/cas/techalerts/TA07-017A.html");
  script_xref(name : "URL" , value : "http://www.appsecinc.com/resources/alerts/oracle/2007-05.shtml");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/474047/100/0/threaded");
  script_id(802523);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2007-0272");
  script_bugtraq_id(22083);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-07 12:25:28 +0530 (Wed, 07 Dec 2011)");
  script_name("Oracle Database Server MDSYS.MD Buffer Overflows and Denial of Service Vulnerabilities");
  script_description(desc);
  script_summary("Check for the version of Oracle Database");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("oracle_tnslsnr_version.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

## Get the port
dbPort = "1521";
if(!get_port_state(dbPort)){
  exit(0);
}

## Get version from KB
dbVer = get_kb_item("oracle_tnslsnr/" + dbPort + "/version");
if(dbVer == NULL){
  exit(0);
}

dbVer = eregmatch(pattern:"Version ([0-9.]+)", string:dbVer);
if(dbVer[1] == NULL){
  exit(0);
}

## Check the affected versions
if(version_in_range(version:dbVer[1], test_version:"8.1.0", test_version2:"8.1.7.3") ||
   version_in_range(version:dbVer[1], test_version:"10.1.0", test_version2:"10.1.0.3") ||
   version_in_range(version:dbVer[1], test_version:"9.0.1", test_version2:"9.0.1.4") ||
   version_in_range(version:dbVer[1], test_version:"9.2.0", test_version2:"9.2.0.6"))
{
  security_hole(data:desc, port:dbPort);
  exit(0);
}

if(report_paranoia < 2){
  exit(0);
}

report=  string("\n\n\n ***** \n" +
                " NOTE : Ignore this warning, if above mentioned patch" +
                " is already applied.\n" +
                " ***** \n");

if(version_is_equal(version:dbVer[1], test_version:"8.1.7.4") ||
   version_is_equal(version:dbVer[1], test_version:"9.0.1.5") ||
   version_is_equal(version:dbVer[1], test_version:"10.1.0.4") ||
   version_is_equal(version:dbVer[1], test_version:"9.2.0.7")){
  security_hole(data:string(desc, report), port:dbPort);
}
