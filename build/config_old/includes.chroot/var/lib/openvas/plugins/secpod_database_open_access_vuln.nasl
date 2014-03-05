###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_database_open_access_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Database Open Access Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_affected = "MySQL
  IBM DB2
  PostgreSQL
  IBM solidDB
  Oracle Database
  Microsoft SQL Server

  Workaround:
  Restrict Database access to remote systems.";

tag_impact = "Successful exploitation could allow an attacker to obtain the sensitive
  information of the database.
  Impact Level: Application";
tag_insight = "Do not restricting direct access of databases to the remote systems.";
tag_summary = "The host is running a Database server and is prone to information
  disclosure vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902799";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-01 17:10:53 +0530 (Thu, 01 Mar 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Database Open Access Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected;

  script_xref(name : "URL" , value : "https://www.pcisecuritystandards.org/security_standards/index.php?id=pci_dss_v1-2.pdf");

  script_description(desc);
  script_copyright("Copyright (C) 2012 SecPod");
  script_summary("Check if given database can be accessible from remote systems");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("oracle_tnslsnr_version.nasl", "gb_ibm_db2_remote_detect.nasl",
                      "postgresql_detect.nasl", "mssqlserver_detect.nasl",
                      "gb_ibm_soliddb_detect.nasl", "mysql_version.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("network_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = 0;
ports = "";
udp_port = "";
udp_ports = "";
oracle_db = "";
ibm_db2 = "";
mysql = "";
mssql = "";
solid_db = "";
postgre_sql = "";
mssql_port = 0;

## Function to check Oracle Database
function is_oracle_db(port)
{
  local_var ver;

  ver = get_kb_item("oracle_tnslsnr/" + port + "/version");
  if(ver){
     return(1);
  }
  else return(0);
}

## Function to check IBM DB2
function is_ibm_db2(port)
{
  local_var ibmVer;

  ibmVer = get_kb_item("IBM-DB2/Remote/ver");
  if(ibmVer){
     return(1);
  }
  else return(0);
}

## Function to check Postgresql
function is_postgre_sql(port)
{
  local_var psqlver;

  psqlver = get_kb_item(string("PostgreSQL/Remote/",port,"/Ver"));
  if(psqlver){
    return(1);
  }
  else return(0);
}

## Function to check SolidDB
function is_solid_db(port)
{
  local_var solidVer;

  solidVer = get_kb_item(string("soliddb/", port, "/version"));
  if(solidVer){
    return(1);
  }
  else return(0);
}

## Function to check MSSQL
function is_mssql()
{
  mssql_port = get_kb_item("Services/mssql");
  if(mssql_port){
    return(1);
  }
  else return(0);
}

## Function to check MySQL
function is_mysql(port)
{
  local_var myVer;

  myVer = get_kb_item(string("mysql/version/", port));
  if(myVer){
   return(1);
  }
  else return(0);
}

## List all running ports
ports = get_kb_list("Ports/tcp/*");
if(isnull(ports)){
  exit(0);
}

foreach port (keys(ports))
{
  ## Grep the port
  port = eregmatch(string:port, pattern:"Ports/tcp/([0-9]+)");

  if(!port[1]){
    continue;
  }

  port = port[1];

  if(!get_tcp_port_state(port)){
    continue;
  }

  ## Checking for oracle database
  oracle_db = is_oracle_db(port:port);
  if(oracle_db == 1)
  {
    log_message(data:string("Oracle database can be accessed by remote attackers"), port:port);
    continue;
  }

  ## Checking for MySQL
  mysql = is_mysql(port:port);
  if(mysql == 1)
  {
    log_message(data:string("MySQL can be accessed by remote attackers"), port:port);
    continue;
  }

  ## Checking for Postgresql
  postgre_sql = is_postgre_sql(port:port);
  if(postgre_sql == 1)
  {
    log_message(data:string("Postgresql database can be accessed by remote attackers"), port:port);
    continue;
  }

  ## Checking for solidDB
  solid_db = is_solid_db(port:port);
  if(solid_db == 1)
  {
    log_message(data:string("SolidDB can be accessed by remote attackers"), port:port);
    continue;
  }
}

## Checking for MS SQL
mssql = is_mssql();
if(mssql == 1){
  log_message(data:string("MS SQL can be accessed by remote attackers"), port:mssql_port);
}


## List all udp ports
udp_ports = get_kb_list("Ports/udp/*");
if(udp_ports)
{
  foreach udp_port (keys(udp_ports))
  {
    ## Grep the port
    udp_port = eregmatch(string:udp_port, pattern:"Ports/udp/([0-9]+)");

    if(!udp_port[1]){
      continue;
    }

    udp_port = udp_port[1];

    if(!get_udp_port_state(udp_port)){
      continue;
    }

    ## Checking for IBM DB2
    ibm_db2 = is_ibm_db2(port:udp_port);
    if(ibm_db2 == 1)
    {
      log_message(data:string("IBM DB2 can be accessed by remote attackers"), port:udp_port, proto: "udp");
      exit(0);
    }
  }
  exit(0);
}

## If get_kb_list("Ports/udp/*") did not list udp ports
## Taking IBM-DB2 default port, manually

udp_port = 523;
if(!get_udp_port_state(udp_port)){
  exit(0);
}

## Checking for IBM DB2
ibm_db2 = is_ibm_db2(port:udp_port);
if(ibm_db2 == 1){
  log_message(data:string("IBM DB2 can be accessed by remote attackers"), port:udp_port, proto: "udp");
}
