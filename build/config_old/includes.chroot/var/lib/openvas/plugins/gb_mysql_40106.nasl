###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_40106.nasl 14 2013-10-27 12:33:37Z jan $
#
# Oracle MySQL 'COM_FIELD_LIST' Command Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
tag_summary = "MySQL is prone to a buffer-overflow vulnerability because it fails to
perform adequate boundary checks on user-supplied data.

An authenticated attacker can leverage this issue to execute arbitrary
code within the context of the vulnerable application. Failed exploit
attempts will result in a denial-of-service condition.

Versions prior to MySQL 5.1.47 are vulnerable.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100646";
CPE = "cpe:/a:mysql:mysql";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-19 12:58:40 +0200 (Wed, 19 May 2010)");
 script_bugtraq_id(40106);
 script_tag(name:"cvss_base", value:"6.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
 script_cve_id("CVE-2010-1850");

 script_name("Oracle MySQL 'COM_FIELD_LIST' Command Buffer Overflow Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40106");
 script_xref(name : "URL" , value : "http://dev.mysql.com/doc/refman/5.1/en/news-5-1-47.html");
 script_xref(name : "URL" , value : "http://bugs.mysql.com/bug.php?id=53237");
 script_xref(name : "URL" , value : "http://www.mysql.com/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed MySQL version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Buffer overflow");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("mysql_version.nasl");
 script_require_ports("Services/mysql", 3306);
 script_require_keys("MySQL/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");
include("misc_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!port)exit(0);
if(!get_tcp_port_state(port))exit(0);

if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);
if(isnull(ver))exit(0);

if(ver =~ "^5\.1\.") {

  if(version_is_less(version: ver, test_version: "5.1.47")) {
    security_hole(port:port);
    exit(0);
  }
}

exit(0);
