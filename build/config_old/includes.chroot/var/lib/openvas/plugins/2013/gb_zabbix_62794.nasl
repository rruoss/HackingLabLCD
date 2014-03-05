###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zabbix_62794.nasl 11 2013-10-27 10:12:02Z jan $
#
# ZABBIX API and Frontend  Multiple SQL Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103812";
CPE = "cpe:/a:zabbix:zabbix";

tag_insight = "A remote attacker could send specially-crafted SQL statements
to multiple API methods using multiple parameters, which could allow the
attacker to view, add, modify or delete information in the back-end database.";

tag_impact = "A successful exploit may allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.";

tag_affected = "ZABBIX prior to 2.0.9
ZABBIX prior to 1.8.18 ";

tag_summary = "ZABBIX API and Frontend are prone to multiple SQL-injection
vulnerabilities.";

tag_solution = "Updates are available. Please see the references or vendor advisory
for more information.";

tag_vuldetect = "Send a special crafted HTTP GET request and check the response.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(62794) ;
 script_cve_id("CVE-2013-5743");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 11 $");

 script_name("ZABBIX API and Frontend  Multiple SQL Injection Vulnerabilities");

 desc = "
Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Impact:
" + tag_impact + "

Affected Software/OS:
" + tag_affected + "

Solution:
" + tag_solution;

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62794");
 script_xref(name:"URL", value:"https://support.zabbix.com/browse/ZBX-7091");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-10-15 14:09:10 +0200 (Tue, 15 Oct 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to inject sql code");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("zabbix_web_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Zabbix/installed");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

url = dir + '/httpmon.php?applications=2%27';

if(http_vuln_check(port:port, url:url,pattern:"Error in query", extra_check:"You have an error in your SQL syntax")) {
  security_hole(port:port);
  exit(0);
}  

exit(99);
