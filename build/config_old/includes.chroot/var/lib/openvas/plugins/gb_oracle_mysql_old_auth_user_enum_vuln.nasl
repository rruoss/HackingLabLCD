###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_mysql_old_auth_user_enum_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# MySQL Authentication Error Message User Enumeration Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation allows attackers to obtain valid usernames, which
  may aid them in brute-force password cracking or other attacks.
  Impact Level: Application";
tag_affected = "MySQL version 5.5.19 and possibly other versions
  MariaDB 5.5.28a, 5.3.11, 5.2.13, 5.1.66 and possibly other versions";
tag_insight = "Mysql server will respond with a different message than Access Denied,
  when attacker authenticates using an incorrect password with the old
  authentication mechanism mysql 4.x and below to a mysql 5.x server.";
tag_solution = "No solution or patch is available as of 07th December, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.mysql.com";
tag_summary = "The host is running MySQL and is prone to user enumeration
  vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802046";
CPE = "cpe:/a:mysql:mysql";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_bugtraq_id(56766);
  script_cve_id("CVE-2012-5615");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-07 16:13:41 +0530 (Fri, 07 Dec 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("MySQL Authentication Error Message User Enumeration Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/88067");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51427");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/23081");
  script_xref(name : "URL" , value : "https://mariadb.atlassian.net/browse/MDEV-3909");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=882608");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2012/12/02/3");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2012/12/02/4");

  script_description(desc);
  script_summary("Determine if MySQL is vulnerable to user enumeration");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Databases");
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


include("host_details.inc");

soc = "";
buf = "";
res2 = "";
sql_port = 0;
initial_res = "";
user_enum_list = "";

## Get MySQL Port
sql_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!sql_port){
  sql_port = 3306;
}

## Check port state
if(!get_port_state(sql_port)){
  exit(0);
}

## Usernames to enumerate
user_enum_list = make_list("root", "admin", "test");

## Need different connection for each user
foreach user (user_enum_list)
{
  ## Open socket
  soc = open_sock_tcp (sql_port);
  if(!soc){
    exit(0);
  }

  ## Initial response
  initial_res = recv(socket:soc, length:1024);
  if(!initial_res || "mysql_native_password" >!< initial_res){
    close(soc);
    exit(0);
  }

  ## Construct old authentication mechanism from mysql 4.x
  ## with incorrect password
  buf = '\x13\x00\x00\x01\x8d\x00\x00\x00\x00' + user +
  '\x00\x50\x4e\x5f\x51\x55\x45\x4d\x45\x00';
  send(socket:soc, data:buf);
  res2 = recv(socket:soc, length:1024);
  close(soc);

  ## Check if mysql is vulnerable to user enumeration
  if("Client does not support authentication protocol" >< res2 &&
     "consider upgrading MySQL client" >< res2 &&
     "Access denied for user" >!< res2 )
  {
    security_warning(sql_port);
    exit(0);
  }
}
