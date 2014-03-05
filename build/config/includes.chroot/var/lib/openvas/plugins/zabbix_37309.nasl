###############################################################################
# OpenVAS Vulnerability Test
# $Id: zabbix_37309.nasl 15 2013-10-27 12:49:54Z jan $
#
# ZABBIX Denial Of Service and SQL Injection Vulnerabilities
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
tag_summary = "ZABBIX is prone to a denial-of-service vulnerability and an SQL-
injection vulnerability.

Successful exploits may allow remote attackers to crash the affected
application, exploit latent vulnerabilities in the underlying
database, access or modify data, or compromise the application.

Versions prior to ZABBIX 1.6.8 are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100406";
CPE = "cpe:/a:zabbix:zabbix";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-12-17 19:46:08 +0100 (Thu, 17 Dec 2009)");
 script_cve_id("CVE-2009-4499", "CVE-2009-4501");
 script_bugtraq_id(37309);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("ZABBIX Denial Of Service and SQL Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://secunia.com/advisories/37740/");
 script_xref(name : "URL" , value : "https://support.zabbix.com/browse/ZBX-1031");
 script_xref(name : "URL" , value : "https://support.zabbix.com/browse/ZBX-1355");
 script_xref(name : "URL" , value : "http://www.zabbix.com/index.php");

 script_description(desc);
 script_summary("Determine if ZABBIX version is < 1.6.8");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("zabbix_detect.nasl","zabbix_web_detect.nasl");
 script_require_ports("Services/www","Services/zabbix_server", 80,10051);
 script_require_keys("Zabbix/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "1.6.8")) {
    
    if(zabbix_port = get_kb_item("Services/zabbix_server")) {
      port = zabbix_port;
    }

    security_hole(port:port);
    exit(0);
  }

}

exit(0);
