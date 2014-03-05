# OpenVAS Vulnerability Test
# $Id: symantec_ws_detection.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Symantec Web Security Detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2007 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_summary = "The remote service filters HTTP / FTP content.

Description :

The remote web server appears to be running Symantec Web Security, 
for filtering traffic of viruses and inappropriate content.";

if(description)
{
 script_id(80019);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "Symantec Web Security Detection";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;
 script_description(desc);
 
 summary = "Checks for SWS";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2007 David Maciejak");
 
 family = "Web application abuses";
 script_family(family);
 script_dependencies("httpver.nasl");
 script_require_ports("Services/www", 8002);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.80019";
SCRIPT_DESC = "Symantec Web Security Detection";

port = get_kb_item("Services/www");
if ( ! port ) port = 8002;

if(get_port_state(port))
{
  banner = get_http_banner(port:port);
  if (
    banner && 
    "Server: SWS-" >< banner
  ) {
    ver = strstr(banner, "Server: SWS-") - "Server: SWS-";
    if (ver) ver = ver - strstr(ver, '\r');
    if (ver) ver = ver - strstr(ver, '\n');
    if (ver && ver =~ "^[0-9]") {
      security_note(port);
      tmp_version = string(ver);
      set_kb_item(name:string("www/", port, "/SWS"),value:tmp_version);
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:symantec:web_security:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
