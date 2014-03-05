###############################################################################
# OpenVAS Vulnerability Test
# $Id: webfileexplorer_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# WebFileExplorer Detection
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
tag_summary = "This host is running WebFileExplorer, a web based file management
  system.";

# need desc here to modify it later in script.
desc = "

 Summary:
 " + tag_summary;


if (description)
{
 script_id(100136);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("WebFileExplorer Detection");  

 script_description(desc);
 script_summary("Checks for the presence of WebFileExplorer");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.webfileexplorer.com/");
 exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100136";
SCRIPT_DESC = "WebFileExplorer Detection";

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port))exit(0);

dirs = make_list("/fileexplorer",cgi_dirs());
foreach dir (dirs) {

 url = string(dir, "/"); 
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);  
 if( buf == NULL )continue;
 
 if(
    egrep(pattern: '<title>WebFileExplorer.*</title>', string: buf, icase: TRUE) &&
    egrep(pattern: 'Set-Cookie: fileoptions.*', string: buf, icase: TRUE))
 { 
     if(strlen(dir)>0) {
        install=dir;
     } else {
        install=string("/");
     }  
    
    vers = string("unknown");

    ### try to get version.
    version = eregmatch(string: buf, pattern: '<title>WebFileExplorer v([0-9.]+)</title>',icase:TRUE, multiline: TRUE);
    
    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    } 
   
    tmp_version = string(vers," under ",install); 
    set_kb_item(name: string("www/", port, "/webfileexplorer"), value:tmp_version);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value: tmp_version, exp:"^([0-9.]+)",base:"cpe:/a:webfileexplorer:web_file_explorer:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    info = string("\n\nWebFileExplorer Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n"); 

    desc = desc + info;    
       
       if(report_verbosity > 0) {
         security_note(port:port,data:desc);
       }
       exit(0);
  
 }
}
exit(0);
