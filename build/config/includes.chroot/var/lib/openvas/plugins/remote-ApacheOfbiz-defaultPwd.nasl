# OpenVAS Vulnerability Test
# $Id: remote-ApacheOfbiz-defaultPwd.nasl 15 2013-10-27 12:49:54Z jan $
# Description: 
# This script the Apache Open For Business (Apache OFBiz) default administrator credentials vulnerability
#
# remote-ApacheOfbiz-defaultPwd.nasl
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
production purposes, please refer to Apache OFBiz documentation, for further
information on how to do this";

tag_summary = "The remote host is running the Apache OFBiz with default administrator username and password. 
Apache OFBiz is an Apache Top Level Project. 
As automation software it comprises a mature suite of enterprise applications that integrate 
and automate many of the business processes of an enterprise.";

if(description)
{
 script_id(101023);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-04-25 21:03:34 +0200 (Sat, 25 Apr 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
name = "Apache Open For Business Weak Password security check";
script_name(name);
 
desc = "
 Summary:
 " + tag_summary + "
 Impact:
 " + tag_impact + "
 Solution:
 " + tag_solution;

script_description(desc); 

summary = "Apache Open For Business (Apache OFBiz) default administrator credentials vulnerability";

script_summary(summary);

script_category(ACT_ATTACK);

script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
script_family("Web Servers");
script_dependencies("find_service.nasl", "remote-detect-ApacheOfbiz.nasl");
script_require_keys("ApacheOFBiz/port");
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

include("openvas-https.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_kb_item("ApacheOFBiz/port");
module = '/webtools/control/login';
report = '';
host = get_host_name();
postdata = string("USERNAME=admin&PASSWORD=ofbiz");

if(!port){
	port = 8443;
	request = string("POST ", module, " HTTP/1.1\r\n",
			 "Content-Type: application/x-www-form-urlencoded\r\n", 
        		 "Content-Length: ", strlen(postdata),"\r\n",
			 "Referer: http://", host, ":", port, module, "\r\n",
		 	 "Host: ", host, 
		 	 "\r\n\r\n",
		 	 postdata);

	reply = https_req_get(port, request);

	if(reply){
	
		welcomeMsg = egrep(pattern:"Welcome THE ADMIN.*", string:reply);
	
		if(welcomeMsg){
			report += "Apache OFBiz said: " + welcomeMsg + "You are using Apache OFBiz with default ADMINISTRATOR username [admin] and pawssord [ofbiz], this can cause security problem in production environment";
		}	
	}
}

if(report)
	security_note(port:port, data:report);
