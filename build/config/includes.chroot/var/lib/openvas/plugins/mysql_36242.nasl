###############################################################################
# OpenVAS Vulnerability Test
# $Id: mysql_36242.nasl 15 2013-10-27 12:49:54Z jan $
#
# MySQL 5.x Unspecified Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "MySQL is prone to a buffer-overflow vulnerability because if fails to
perform adequate boundary checks on user-supplied data.

An attacker can leverage this issue to execute arbitrary code within
the context of the vulnerable application. Failed exploit attempts
will result in a denial-of-service condition.

This issue affects MySQL 5.x; other versions may also be vulnerable.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100271";
CPE = "cpe:/a:mysql:mysql";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-07 09:47:24 +0200 (Mon, 07 Sep 2009)");
 script_bugtraq_id(36242);
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");

 script_name("MySQL 5.x Unspecified Buffer Overflow Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36242");
 script_xref(name : "URL" , value : "http://www.mysql.com/");
 script_xref(name : "URL" , value : "http://intevydis.com/company.shtml");

 script_description(desc);
 script_summary("Determine if mysql version is <= 5.1.32 ");
 script_category(ACT_GATHER_INFO);
 script_family("Databases");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
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
if(!get_tcp_port_state(port))exit(0);

if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);
ver = eregmatch(pattern:"[0-9.]+", string: ver);

if(isnull(ver[0]))exit(0);

if(version_in_range(version:ver[0], test_version:"5", test_version2:"5.1.32") ) {
     security_hole(port:port);
     exit(0);
}

exit(0);