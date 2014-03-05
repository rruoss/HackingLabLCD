# OpenVAS Vulnerability Test
# $Id: remote-detect-WindowsSharepointServices.nasl 43 2013-11-04 19:51:40Z jan $
#
# Description: This script ensure that Windows SharePointServices is
# installed and running
#
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# TODO: implement service pack gathering using the minor version number
# source: http://www.microsoft.com/downloads/details.aspx?FamilyId=D51730B5-48FC-4CA2-B454-8DC2CAF93951&displaylang=en#Requirements
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
tag_summary = "The remote host is running Windows SharePoint Services.  
Microsoft SharePoint products and technologies include browser-based collaboration and a document-management platform. 
These can be used to host web sites that access shared workspaces and documents from a browser.";

tag_solution = "It's recommended to allow connection to this host only from trusted hosts or networks.";

if(description)
{
script_id(101018);
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
script_tag(name:"creation_date", value:"2009-04-01 22:29:14 +0200 (Wed, 01 Apr 2009)");
script_tag(name:"cvss_base", value:"0.0");
script_tag(name:"risk_factor", value:"None");
name = "Windows SharePoint Services detection";
script_name(name);
 
desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;
script_description(desc); 

summary = "Windows SharePoint Services Information Gathering";

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
include("cpe.inc");
include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.101018";
SCRIPT_DESC = "Windows SharePoint Services detection";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
port = get_http_port(default:80);

# request a non existant random page
page = string(rand() + "openvas.aspx");
thehost = get_host_name();

request = string(
    "GET /", page, " HTTP/1.0\r\n",
    "Host: ", thehost ,"\r\n",
    "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko/2009032711 Ubuntu/8.10 (intrepid) Firefox/3.0.8\r\n",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
    "Accept-Encoding: gzip,deflate\r\n",
    "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
    "Accept-Language: en-us,en;q=0.5\r\n",
    "Keep-Alive: 300\r\n",
    "Connection: keep-alive\r\n\r\n"
    );

report = '';

if(port){
	response = http_keepalive_send_recv(port:port, data:request, bodyonly:0);

	if(response){
	
	  if("microsoft" >!< tolower(response))exit(0);

		dotNetServer = eregmatch(pattern:"Server: Microsoft-IIS/([0-9.]+)",string:response, icase:TRUE);
	        mstsVersion = eregmatch(pattern:"MicrosoftSharePointTeamServices: ([0-9.]+)",string:response, icase:TRUE);
		xPoweredBy = eregmatch(pattern:"X-Powered-By: ([a-zA-Z.]+)",string:response, icase:TRUE);
	        aspNetVersion = eregmatch(pattern:"X-AspNet-Version: ([0-9.]+)",string:response, icase:TRUE);

		if(mstsVersion){
			
			# TODO: extract the service pack using the [0-9] pattern (minor version number)
			wssVerion = '';

			set_kb_item(name:"WindowsSharePointServices/installed", value:TRUE);
			set_kb_item(name:"MicrosoftSharePointTeamServices/version", value:mstsVersion[1]);

                        ## build cpe and store it as host_detail
                        register_host_detail(name:"App", value:"cpe:/a:microsoft:sharepoint_team_services:2007", nvt: SCRIPT_OID, desc:SCRIPT_DESC);
			
			if( eregmatch(pattern:"(6.0.2.[0-9]+)", string:mstsVersion[1], icase:TRUE) ){
				wssVersion = "2.0";
				set_kb_item(name:"WindowsSharePointServices/version", value:wssVerion);

                                ## build cpe and store it as host_detail
                                register_cpe(tmpVers:wssVersion, tmpExpr:"^([0-9]\.[0-9])", tmpBase:"cpe:/a:microsoft:sharepoint_services:");

			}
			if( eregmatch(pattern:"(12.[0-9.]+)", string:mstsVersion[1], icase:TRUE) ){
				wssVersion = "3.0";
				set_kb_item(name:"WindowsSharePointServices/version", value:wssVersion);

                                ## build cpe and store it as host_detail
                                register_cpe(tmpVers:wssVersion, tmpExpr:"^([0-9]\.[0-9])", tmpBase:"cpe:/a:microsoft:sharepoint_services:");

			}

			report = "Detected: " + mstsVersion[0];	
			if(wssVersion)
				report += "\n" + "Windows SharePoint Services " + wssVersion;
		}
		if(dotNetServer){

			# OS fingerprint using IIS signature
			osVersion = '';
			if( eregmatch(pattern:"(7.[0-4]+)", string:dotNetServer[1], icase:TRUE) ){
				osVersion = "Windows 2008 / Vista";
				set_kb_item(name:"wssOS/version", value:osVersion);
			}
			if( eregmatch(pattern:"(7.[5-9]+)", string:dotNetServer[1], icase:TRUE) ){
				osVersion = "Windows 2008 R2 / Windows 7";
				set_kb_item(name:"wssOS/version", value:osVersion);
			}
			if( eregmatch(pattern:"(6.[0-9]+)", string:dotNetServer[1], icase:TRUE) ){
				osVersion = "Windows Server 2003 / Windows XP Professional x64";
				set_kb_item(name:"wssOS/version", value:osVersion);
			}
			if( eregmatch(pattern:"(5.1)", string:dotNetServer[1], icase:TRUE) ){
				osVersion = "Windows XP";
				set_kb_item(name:"wssOS/version", value:osVersion);

			}
			if( eregmatch(pattern:"(5.0)", string:dotNetServer[1], icase:TRUE) ){
				osVersion = "Windows Server 2000";
				set_kb_item(name:"wssOS/version", value:osVersion);
			}

			set_kb_item(name:"Microsoft-IIS/installed", value:TRUE);	
			set_kb_item(name:"Microsoft-IIS/version", value:dotNetServer[1]); 	

                        ## build cpe and store it as host_detail
                        register_cpe(tmpVers: dotNetServer[1], tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:microsoft:iis:");

			report += "\n" + dotNetServer[0];
			if( osVersion ){
				report += "\n" + "Operating System Type: " + osVersion;
                        }
		}
		if(aspNetVersion){		
			set_kb_item(name:"aspNetVersion/version", value:aspNetVersion[1]);	
			report += "\n" + aspNetVersion[0];
		
			if(xPoweredBy){
				set_kb_item(name:"ASPX/enabled", value:TRUE);
				report += "\n" + xPoweredBy[0];	
			}
		}
	}
}
if ( report ) {		
	security_note(port:port, data:report);
}
