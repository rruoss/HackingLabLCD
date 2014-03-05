###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_database_n_appln_server_pl_sql_cmd_exec_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Oracle Database Server and Application Server Multiple Unspecified Vulnerabilities
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
tag_impact = "Successful exploitation allows an attackers to send a specially-crafted HTTP
  request to bypass the PLSQLExclusion list and execute SQL commands on the
  back-end database with DBA privileges.
  Impact Level: Application";
tag_affected = "Oracle Database server versions 9.2.0.7 and 10.1.0.5
  Oracle Application server versions 1.0.2.2, 9.0.4.2, 10.1.2.0.2, 10.1.2.1 and
  10.1.3.0.0";
tag_insight = "The flaw is due to error in Oracle PL/SQL Gateway, which fails to
  properly validate user-supplied HTTP requests.";
tag_solution = "Apply patches from below link,
  http://www.oracle.com/technetwork/topics/security/cpuapr2006-090826.html";
tag_summary = "This host is running Oracle database or application server and
  is prone to SQL command execution vulnerability.";

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

report = string("\n\n\n ***** \n" +
                " NOTE : Ignore this warning, if above mentioned patch" +
                " is already applied.\n" +
                " ***** \n");

if(description)
{
  script_xref(name : "URL" , value : "http://osvdb.org/22719");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/169164");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1015961");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/24363");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/423822/100/0/threaded");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/423819/100/0/threaded");
  script_id(802525);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2006-0435");
  script_bugtraq_id(16384);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-07 12:32:19 +0530 (Wed, 07 Dec 2011)");
  script_name("Oracle Database Server and Application Server Multiple Unspecified Vulnerabilities");
  script_description(desc);
  script_summary("Check for the version of Oracle Database and Application server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
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


include("http_func.inc");
include("version_func.inc");

## Oracle Database Server ##

## Get the port
dbPort = "1521";
if(get_port_state(dbPort))
{
  ## Get version from KB
  dbVer = get_kb_item("oracle_tnslsnr/" + dbPort + "/version");
  if(dbVer != NULL)
  {
    dbVer = eregmatch(pattern:"Version ([0-9.]+)", string:dbVer);
    if(dbVer[1] != NULL)
    {
      ## Check the affected versions
      if(version_in_range(version:dbVer[1], test_version:"9.2.0", test_version2:"9.2.0.6") ||
         version_in_range(version:dbVer[1], test_version:"10.1.0", test_version2:"10.1.0.4"))
      {
        security_hole(data:desc, port:dbPort);
        exit(0);
      }

      if(report_paranoia < 2){
        exit(0);
      }

      if(version_is_equal(version:dbVer[1], test_version:"9.2.0.7") ||
         version_is_equal(version:dbVer[1], test_version:"10.1.0.5")){
          security_hole(data:string(desc, report), port:dbPort);
      }
    }
  }
}

## Oracle Application Server ##
## Get the port

appPort = "7777";
if(!get_port_state(appPort)){
  exit(0);
}

## Get the banner
banner = get_http_banner(port:appPort);

## Confirm the server
if(banner && "Oracle-Application-Server" >< banner)
{
  ## Grep for version
  appVer = eregmatch(pattern:"Oracle-Application-Server-[0-9a-zA-Z]+?/([0-9.]+)",
                                             string:banner);
  if(appVer[1] == NULL){
    exit(0);
  }

  ## Check the affected versions
  if(version_is_less(version:appVer[1], test_version:"1.0.2.1") ||
     version_in_range(version:appVer[1], test_version:"9.0", test_version2:"9.0.4.1") ||
     version_in_range(version:appVer[1], test_version:"10.1.2.0", test_version2:"10.1.3.0"))
  {
    security_hole(data:desc, port:appPort);
    exit(0);
  }

  if(report_paranoia < 2){
    exit(0);
  }

  if(version_is_equal(version:appVer[1], test_version:"9.0.4.2") ||
     version_is_equal(version:appVer[1], test_version:"1.0.2.2") ||
     version_is_equal(version:appVer[1], test_version:"10.1.2.1")){
    security_hole(data:string(desc, report), port:appPort);
  }
}
