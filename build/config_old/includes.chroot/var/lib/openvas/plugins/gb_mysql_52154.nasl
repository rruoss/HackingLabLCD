###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_52154.nasl 12 2013-10-27 11:15:33Z jan $
#
# MySQL 5.5.20 Unspecified Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "MySQL is prone to an unspecified remote code-execution vulnerability.

Very few technical details are currently available. We will update
this BID as more information emerges.

An attacker can leverage this issue to execute arbitrary code within
the context of the vulnerable application. Failed exploit attempts
will result in a denial-of-service condition.

MySQL 5.5.20 is vulnerable; other versions may also be vulnerable.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103472";
CPE = "cpe:/a:mysql:mysql";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(52154);
 script_version ("$Revision: 12 $");

 script_name("MySQL 5.5.20 Unspecified Remote Code Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52154");
 script_xref(name : "URL" , value : "https://lists.immunityinc.com/pipermail/canvas/2012-February/000014.html");
 script_xref(name : "URL" , value : "http://www.intevydis.com/index.shtml");
 script_xref(name : "URL" , value : "http://www.mysql.com/");

 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-04-19 11:48:24 +0200 (Thu, 19 Apr 2012)");
 script_description(desc);
 script_summary("Determine if installed MySQL version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Databases");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("mysql_version.nasl");
 script_require_ports("Services/mysql", 3306);
 script_require_keys("MySQL/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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
  if(version_is_equal(version:mysqlVer[1], test_version:"5.5.20")){
    security_hole(port:sqlPort);
    exit(0);
  }
}
