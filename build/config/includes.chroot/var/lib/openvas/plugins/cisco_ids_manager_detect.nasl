###################################################################
# OpenVAS Network Vulnerability Test
#
# Cisco IDS Manager Detection
#
# LSS-NVT-2009-006
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2009 LSS <http://www.lss.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

include("revisions-lib.inc");
tag_summary = "Detects if CISCO IDS Manager is running on a given host and port.

The IDS Device Manager is a web-based Java application that resides
on the sensor and is accessed via a secure, encrypted TLS link using
standard Netscape and Internet Explorer web browsers to perform
various management and monitoring tasks.";

if(description)
{
 script_id(102006);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-06-23 09:27:52 +0200 (Tue, 23 Jun 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 name = "CISCO IDS Manager Detection";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);

 summary = "Detects CISCO IDS Manager on a remote host";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (C) 2009 LSS");
 family = "Service detection";
 script_family(family);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("openvas-https.inc");


port = get_kb_item("Services/www");
if(!port)    port = 443;
if(!get_port_state(port)){
    exit(-1);
}

sock = open_sock_tcp(port);
req = http_get(item:"/", port:port);
body = https_req_get(port: port, request: req);
if("<title>Cisco Systems IDS Device Manager</title>" >< body){
    dscr = "
CISCO IDS Manager is running on a given host and port.

The IDS Device Manager is a web-based Java application that resides
on the sensor and is accessed via a secure, encrypted TLS link using
standard Netscape and Internet Explorer web browsers to perform
various management and monitoring tasks.
";
    security_note(data: dscr, port: port);
    set_kb_item(name:"Services/www/cisco_ids_manager", value:TRUE);
    set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
}

