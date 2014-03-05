###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# IBM WebSphere Application Server Detection
#
# Authors:
# Michael Meyer
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
tag_summary = "This host is running the IBM WebSphere Application Server.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 
 script_id(100564);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2010-04-01 13:43:26 +0200 (Thu, 01 Apr 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("IBM WebSphere Application Server Detection");

 script_description(desc);
 script_summary("Checks for the presence of IBM WebSphere Application Server");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www-01.ibm.com/software/webservers/appserv/was/");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100564";
SCRIPT_DESC = "IBM WebSphere Application Server Detection";

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
if("Server: WebSphere Application Server/" >!< banner )exit(0);

url = string("/");
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if( res == NULL )exit(0);

if(egrep(pattern: "WASRemoteRuntimeVersion", string: res, icase: TRUE)) {
  
  vers = string("unknown");
  
  version = eregmatch(pattern:'WASRemoteRuntimeVersion="([^"]+)"', string:res);  

  if(!isnull(version[1])) {
    vers = version[1];
    register_host_detail(name:"App", value:string("cpe:/a:ibm:websphere_application_server:",vers), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
  } else {
    register_host_detail(name:"App", value:string("cpe:/a:ibm:websphere_application_server"), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
  }  

  set_kb_item(name:string("www/",port,"/websphere_application_server"), value: vers);

  info = string("was/\n\nWebSphere Application Server Version '");
  info += string(vers);
  info += string("' was detected on the remote host\n\n");

  desc = ereg_replace(
	     string:desc,
	     pattern:"was/$",
	     replace:info
	     );    

  if(report_verbosity > 0) {
    security_note(port:port,data:desc);
    exit(0); 
   }
}
exit(0);

