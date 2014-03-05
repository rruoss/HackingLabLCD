# OpenVAS Vulnerability Test
# $Id: remote-detect-ApacheOfbiz.nasl 15 2013-10-27 12:49:54Z jan $
# Description: This script ensure that the Apache Open For Business (Apache OFBiz) is installed and running
#
# remote-detect-ApacheOfbiz.nasl
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
tag_summary = "The remote host is running the Apache OFBiz. 
Apache OFBiz is an Apache Top Level Project. 
As automation software it comprises a mature suite of enterprise applications that integrate 
and automate many of the business processes of an enterprise.";

tag_solution = "It's recommended to allow connection to this host only from trusted hosts or networks,
or disable the service if not used.";



if(description)
{
script_id(101019);
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2009-04-18 23:46:40 +0200 (Sat, 18 Apr 2009)");
script_tag(name:"cvss_base", value:"0.0");
script_tag(name:"risk_factor", value:"None");
name = "Apache Open For Business service detection";
script_name(name);
 
desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;
script_description(desc); 

summary = "Detect a running Apache Open For Business automation suite";

script_summary(summary);

script_category(ACT_GATHER_INFO);

script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
family = "Service detection";
script_family(family);
script_dependencies("find_service.nasl");
script_require_ports("Services/www");


if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
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

# TODO: iterate all possible https port
port = 8443;
 
modules = make_list('accounting/control/main','partymgr/control/main','webtools/control/main','ordermgr/control/main');
report = '';

foreach module (modules){
	request = string("GET /", module, " HTTP/1.1\r\n","Host: ", get_host_name(), "\r\n\r\n");

	reply = https_req_get(port, request);


	if(reply){
		response = tolower(reply);

		servletContainer = eregmatch(pattern:"Server: Apache-Coyote/([0-9.]+)",string:response, icase:TRUE);
		ofbizTitlePattern = eregmatch(pattern:"<title>([a-zA-Z: ]+)</title>",string:response, icase:TRUE);
		vendor = eregmatch(pattern:'powered by <a href="http://ofbiz.apache.org" target="_blank">([a-zA-Z ]+) ([0-9.]+)',string:response, icase:TRUE);

		if(ofbizTitlePattern){
			if('ofbiz' >< ofbizTitlePattern[1]){
				report += " Detected Apache Open For Business Module[" + ofbizTitlePattern[1] +"] ";
				replace_kb_item(name:"ApacheOFBiz/installed", value:TRUE);
				replace_kb_item(name:"ApacheOFBiz/port", value:port);
		
				if(vendor){
					report += "\n Detected " + vendor[1] + " " + vendor[2];
					replace_kb_item(name:"ApacheOFBiz/version", value:vendor[2]);
				}

				if((servletContainer)){
					replace_kb_item(name:"ApacheCoyote/installed", value:TRUE);
					replace_kb_item(name:"ApacheCoyote/version", value:servletContainer[1]);
					report += " on " + servletContainer[0];
				}
			}
		}
	}
	if(report)
		security_note(port:port, data:report);
}
