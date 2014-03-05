# OpenVAS Vulnerability Test
# $Id: DDI_GlobalASA_Retrieval.nasl 17 2013-10-27 14:01:43Z jan $
# Description: IIS Global.asa Retrieval
#
# Authors:
# H D Moore
#
# Copyright:
# Copyright (C) 2001 Digital Defense Inc.
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
tag_summary = "This host is running the Microsoft IIS web server.  This web server contains 
a configuration flaw that allows the retrieval of the global.asa file.  

This file may contain sensitive information such as database passwords, 
internal addresses, and web application configuration options.  This 
vulnerability may be caused by a missing ISAPI map of the .asa extension 
to asp.dll.";

tag_solution = "To restore the .asa map:

    Open Internet Services Manager. Right-click on the affected web server and choose Properties 
    from the context menu. Select Master Properties, then Select WWW Service --> Edit --> Home 
    Directory --> Configuration. Click the Add button, specify C:\winnt\system32\inetsrv\asp.dll 
    as the executable (may be different depending on your installation), enter .asa as the extension, 
    limit the verbs to GET,HEAD,POST,TRACE, ensure the Script Engine box is checked and click OK.";


if(description)
{
    script_id(10991);
    script_version("$Revision: 17 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
    script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"7.8");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
    script_tag(name:"risk_factor", value:"High");
    name = "IIS Global.asa Retrieval";
    script_name(name);


    desc = "
    Summary:
    " + tag_summary + "
    Solution:
    " + tag_solution;

    script_description(desc);

    summary = "Tries to retrieve the global.asa file";

    script_summary(summary);


    script_category(ACT_ATTACK);

    script_copyright("This script is Copyright (C) 2001 Digital Defense Inc.");

    family = "Web application abuses";
    script_family(family);
    script_dependencies("find_service.nasl", "http_version.nasl");
    script_require_ports("Services/www", 80);
    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "solution" , value : tag_solution);
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
}


#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port)){ exit(0); }
sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

function sendrequest (request, port)
{
    return http_keepalive_send_recv(port:port, data:request);
}

req = http_get(item:"/global.asa", port:port);
reply = sendrequest(request:req, port:port);
if ("RUNAT" >< reply)
{
    security_hole(port:port);
    set_kb_item(name:"iis/global.asa.download", value:TRUE);
}
