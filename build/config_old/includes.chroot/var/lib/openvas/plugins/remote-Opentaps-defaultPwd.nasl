# OpenVAS Vulnerability Test
# $Id: remote-Opentaps-defaultPwd.nasl 15 2013-10-27 12:49:54Z jan $
# Description: 
# This script the Opentaps ERP + CRM default administrator credentials vulnerability
#
# remote-Opentaps-defaultPwd.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_impact = "This allow an attacker to gain administrative access to the remote application";

tag_solution = "You must change the default settings if you want to run it for
production purposes, please refer to the Opentaps ERP + CRM documentation, for
further information on how to do this";

tag_summary = "The remote host is running the Apache OFBiz with default administrator username and password. 
Opentaps is a full-featured ERP + CRM suite which incorporates several open source projects, 
including Apache Geronimo, Tomcat, and OFBiz for the data model and transaction framework; 
Pentaho and JasperReports for business intelligence; Funambol for mobile device and Outlook integration; 
and the opentaps applications which provide user-driven applications for CRM, accounting and finance, 
warehouse and manufacturing, and purchasing and supply chain mmanagement.";

if(description)
{
script_id(101024);
script_version("$Revision: 15 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2009-04-25 22:17:58 +0200 (Sat, 25 Apr 2009)");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"risk_factor", value:"High");
name = "Opentaps ERP + CRM Weak Password security check";
script_name(name);
 
desc = "
Summary:
" + tag_summary + "
Impact:
" + tag_impact + "
Solution:
" + tag_solution;

script_description(desc); 

summary = "Opentaps ERP + CRM default administrator credentials vulnerability";

script_summary(summary);

script_category(ACT_ATTACK);

script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
script_family("Web application abuses");
script_dependencies("find_service.nasl", "remote-detect-Opentaps_ERP_CRM.nasl");
script_require_keys("OpentapsERP/port");
script_require_ports("Services/www");


if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "impact" , value : tag_impact);
}
exit(0);

}

#
# The script code starts here
#

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_kb_item("OpentapsERP/port");
module = '/webtools/control/login';
report = '';
host = get_host_name();
postdata = string("USERNAME=admin&PASSWORD=ofbiz");

if(!port){
	port = 8080;
	request = string("POST ", module, " HTTP/1.1\r\n",
			 "Content-Type: application/x-www-form-urlencoded\r\n", 
        		 "Content-Length: ", strlen(postdata), "\r\n",
 			 "Referer: http://", host, ":", port, module, "\r\n",
		 	 "Host: ", host, 
		 	 "\r\n\r\n",
		 	 postdata);

	reply = http_send_recv(port:port, data:request);

	if(reply){
	
		welcomeMsg = egrep(pattern:"Welcome THE ADMIN.*", string:reply);
	
		if(welcomeMsg){
			report += "Opentaps ERP + CRM said: " + welcomeMsg + "this application is running using default ADMINISTRATOR username [admin] and pawssord [ofbiz], this can cause security problem in production environment";
		}	
	}
}

if(report)
	security_note(port:port, data:report);
