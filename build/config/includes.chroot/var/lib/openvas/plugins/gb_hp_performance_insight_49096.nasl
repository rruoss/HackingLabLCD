###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_performance_insight_49096.nasl 72 2013-11-21 17:10:44Z mime $
#
# HP OpenView Performance Insight Security Bypass and HTML Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "HP OpenView Performance Insight is prone to a security-bypass
vulnerability and an HTML-injection vulnerability.

An attacker may leverage the HTML-injection issue to inject hostile
HTML and script code that would run in the context of the affected
site, potentially allowing the attacker to steal cookie-based
authentication credentials or to control how the site is rendered
to the user.

The attacker may leverage the security-bypass issue to bypass certain
security restrictions and perform unauthorized actions in the affected
application.";

tag_solution = "Vendor updates are available. Please see the references for details.";

if (description)
{
 script_id(103200);
 script_version("$Revision: 72 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-21 18:10:44 +0100 (Thu, 21 Nov 2013) $");
 script_tag(name:"creation_date", value:"2011-08-16 15:29:48 +0200 (Tue, 16 Aug 2011)");
 script_bugtraq_id(49096);
 script_cve_id("CVE-2011-2406", "CVE-2011-2407", "CVE-2011-2410");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

 script_name("HP OpenView Performance Insight Security Bypass and HTML Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if HP OpenView Performance Insight is prone to a HTML-injection vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_hp_performance_insight_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49096");
 script_xref(name : "URL" , value : "https://h10078.www1.hp.com/cda/hpms/display/main/hpms_content.jsp?zn=bto&amp;amp;cp=1-11-15-119^1211_4000_100");
 script_xref(name : "URL" , value : "http://h20566.www2.hp.com/portal/site/hpsc/public/kb/docDisplay/?docId=emr_na-c02942411&amp;ac.admitted=1312903473487.876444892.199480143");
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:8080);
if( ! get_port_state( port ) ) exit(0);

if( ! dir = get_dir_from_kb(port:port,app:"hp_openview_insight") ) exit(0);
url = string(dir,"/jsp/sendEmail.jsp",'">',"<script>alert('openvas-xss-test')</script>");

if(http_vuln_check(port:port, url:url, pattern:"<body bgcolor=.<script>alert\('openvas-xss-test'\)</script>")) {
     
    security_hole(port:port);
    exit(0);

  }

exit(0);

