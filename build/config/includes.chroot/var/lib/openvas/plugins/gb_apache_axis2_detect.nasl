###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_axis2_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# Apache Axis2 Detection
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
tag_summary = "This host is running Apache Axis2, a Web Services / SOAP / WSDL
engine, the successor to the widely used Apache Axis  SOAP stack.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 
 script_id(100813);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-09-20 15:31:27 +0200 (Mon, 20 Sep 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Apache Axis2 Detection");

 script_description(desc);
 script_summary("Checks for the presence of Apache Axis2");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080,8081);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://ws.apache.org/axis2/");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100813";
SCRIPT_DESC = "Apache Axis2 Detection";

port = get_http_port(default:8081);
if(!get_port_state(port))exit(0);

dirs = make_list("/axis2",cgi_dirs());

foreach dir (dirs) {

 url = string(dir, "/services/Version/getVersion");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;

 if(egrep(pattern: "Hello I am Axis2", string: buf, icase: TRUE))
 {
     if(strlen(dir)>0) {
        install=dir;
     } else {
        install=string("/");
     }

    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: buf, pattern: "My version is ([0-9.]+)",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }

    set_kb_item(name: string("www/", port, "/axis2"), value: string(vers," under ",install));

    if(vers != "unknown") {
      register_host_detail(name:"App", value:string("cpe:/a:apache:axis2:",vers), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    } else {
      register_host_detail(name:"App", value:string("cpe:/a:apache:axis2:"), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    }  

    info = string("/\n\nApache Axis2 Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n");

    desc = ereg_replace(
        string:desc,
        pattern:"/$",
        replace:info
    );

       if(report_verbosity > 0) {
         security_note(port:port,data:desc);
       }
       exit(0);

 }
}
exit(0);

