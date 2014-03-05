# OpenVAS Vulnerability Test
# $Id: DDI_IIS_dotNet_Trace.nasl 17 2013-10-27 14:01:43Z jan $
# Description: IIS ASP.NET Application Trace Enabled
#
# Authors:
# H D Moore
#
# Copyright:
# Copyright (C) 2002 Digital Defense Inc.
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
tag_summary = "The ASP.NET web application running in the root
directory of this web server has application
tracing enabled. This would allow an attacker to
view the last 50 web requests made to this server,
including sensitive information like Session ID values
and the physical path to the requested file.";

tag_solution = "Set <trace enabled=false> in web.config";

if(description)
{
    script_id(10993);
    script_version("$Revision: 17 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
    script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"7.8");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
    script_tag(name:"risk_factor", value:"High");
    name = "IIS ASP.NET Application Trace Enabled";
    script_name(name);


    desc = "
    Summary:
    " + tag_summary + "
    Solution:
    " + tag_solution;
    script_description(desc);

    summary = "Checks for ASP.NET application tracing";
    script_summary(summary);


    script_category(ACT_ATTACK);

    script_copyright("This script is Copyright (C) 2002 Digital Defense Inc.");

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


req = http_get(item:"/trace.axd", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ("Application Trace" >< res)
{
    security_hole(port:port);
}
