###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_JBoss_enterprise_aplication_server_45148.nasl 14 2013-10-27 12:33:37Z jan $
#
# JBoss Enterprise Application Platform Multiple Remote Vulnerabilities
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100931";
CPE = 'cpe:/a:redhat:jboss_enterprise_application_platform';

tag_summary = "The JBoss Enterprise Application Platform is prone to multiple
vulnerabilities, including a remote code-execution issue, a remote denial-of-
service issue, and a cross-site request-forgery issue.

Successful exploits can allow attackers to execute arbitrary
code within the context of the affected application, perform
certain administrative actions, deploy arbitrary WAR files on
the server, or cause denial-of-service conditions; other attacks
may also be possible.

These issues affect JBoss Enterprise Application Platform 4.3.0; other
versions may also be affected.";

tag_solution = "Updates are available; please see the references for more information.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-12-02 19:42:22 +0100 (Thu, 02 Dec 2010)");
 script_bugtraq_id(45148);
 script_cve_id("CVE-2010-3708","CVE-2010-3862","CVE-2010-3878");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("JBoss Enterprise Application Platform Multiple Remote Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45148");
 script_xref(name : "URL" , value : "http://www.jboss.com/products/platforms/application/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed JBoss version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("JBoss_enterprise_aplication_server_detect.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("jboss_enterprise_application_server/installed");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }

 exit(0);

}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if("cp" >< vers) {
    vers = str_replace(string:vers,find:"cp", replace:"."); 
  }  
 
  if("GA" >< vers)vers = vers - ".GA";

  if(version_is_less(version: vers, test_version: "4.3.0.9")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);


