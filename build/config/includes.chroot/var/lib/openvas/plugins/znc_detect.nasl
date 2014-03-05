###############################################################################
# OpenVAS Vulnerability Test
# $Id: znc_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# ZNC Detection
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
tag_summary = "This host is running ZNC, an IRC Bouncer.";

# need desc here to modify it later in script.

desc = "

 Summary:
 " + tag_summary;


if (description)
{
 script_id(100243);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-07-26 19:54:54 +0200 (Sun, 26 Jul 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("ZNC Detection");

 script_description(desc);
 script_summary("Checks for the presence of ZNC");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "find_service2.nasl","http_version.nasl");
 script_require_ports("Services/irc", 6667);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://en.znc.in/wiki/ZNC");
 exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("global_settings.inc");
include("ssl_funcs.inc");
include("http_func.inc");
include("misc_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100243";
SCRIPT_DESC = "ZNC Detection";

port = get_kb_item("Services/irc");
if (!port) port = 6667;
if(! get_port_state(port)) exit(0);

if(cert = get_server_cert(port)) {
  transport = ENCAPS_SSLv23;
} else {
  transport = ENCAPS_IP;
}  

soc = open_sock_tcp(port,transport:transport);
if (! soc) exit(0);

req=string("USER\r\n");
send(socket: soc, data: req);

buf = recv_line(socket:soc, length:64);
close(soc);

 if(egrep(pattern:"irc\.znc\.in NOTICE AUTH" , string: buf, icase: TRUE)) {
       
       set_kb_item(name:"Services/irc/" + port + "/znc", value:TRUE);
       kb_transport = get_port_transport(port);
       
       if(kb_transport < transport) {
	 replace_kb_item(name: string("Transports/TCP/",port), value: transport);
       }
      
       if(banner = get_http_banner(port:port)) { # only way to get version is from webadmin-module (if enabled). 

          version = eregmatch(string: banner, pattern: "Server: ZNC ([0-9.]+)",icase:TRUE);

	  if ( !isnull(version[1]) ) {
            vers=version[1];
            set_kb_item(name: string("znc/", port, "/version"), value: vers);
       
            ## build cpe and store it as host_detail
            cpe = build_cpe(value: vers, exp:"^([0-9.]+)",base:"cpe:/a:znc:znc:");
            if(!isnull(cpe))
               register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

            info = string("\n\nZNC Version '");
            info += string(vers);
            info += string("' was detected on the remote host\n");

            desc = desc + info;
        }	
       }
	 
       if(report_verbosity > 0) {
         security_note(port:port,data:desc);
       }
       exit(0);
 }

exit(0);

