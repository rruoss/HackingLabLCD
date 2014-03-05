###############################################################################
# OpenVAS Vulnerability Test
# $Id: atmail_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Atmail Detection
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
tag_summary = "Detection of Atmail.

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100148";

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-04-17 18:35:24 +0200 (Fri, 17 Apr 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 script_name("Atmail Detection");  
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_summary("Checks for the presence of Atmail");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

## Constant values
SCRIPT_DESC = "Atmail Detection";

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/mail","/webmail","/atmail",cgi_dirs());
foreach dir (dirs) {

 url = string(dir, "/index.php"); 
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);  
 if( buf == NULL )continue;
 
 if(
    egrep(pattern: "Powered by Atmail", string: buf, icase: TRUE) ||
    egrep(pattern: "<title>Login to Atmail</title>", string: buf) ||
    egrep(pattern: "For more information on the WebMail service.*Atmail PHP [0-9.]+", string: buf)) 
 { 
     if(strlen(dir)>0) {
        install=dir;
     } else {
        install=string("/");
     }  
    
    vers = string("unknown");

    ### try to get version.
    version = eregmatch(string: buf, pattern: "Powered by Atmail ([0-9.]+)",icase:TRUE);
    
     if ( !isnull(version[1]) ) {
        vers=version[1];
     } else {

       version = eregmatch(string: buf, pattern: "For more information on the WebMail service, please contact.*Atmail PHP ([0-9.]+)",icase:TRUE);

       if ( !isnull(version[1]) ) {
	 vers=version[1];
       }	 
     }  
    
    tmp_version = string(vers," under ",install);
    set_kb_item(name: string("www/", port, "/atmail"), value: tmp_version);
    set_kb_item(name:"Atmail/installed",value:TRUE);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)",base:"cpe:/a:atmail:atmail:");
    if(isnull(cpe))
      cpe = 'cpe:/a:atmail:atmail';

    register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);

    log_message(data: build_detection_report(app:"Atmail", version:vers, install:install, cpe:cpe, concluded: version[0]),
                port:port);

    exit(0);

 }
}

exit(0);
