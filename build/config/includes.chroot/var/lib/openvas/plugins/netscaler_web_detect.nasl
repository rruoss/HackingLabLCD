# OpenVAS Vulnerability Test
# $Id: netscaler_web_detect.nasl 16 2013-10-27 13:09:52Z jan $
# Description: NetScaler web management interface detection
#
# Authors:
# nnposter
#
# Copyright:
# Copyright (C) 2007 nnposter
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
tag_summary = "A Citrix NetScaler web management interface is running on this port. 

Description :

The remote host appears to be a Citrix NetScaler, an appliance for web
application delivery, and the remote web server is its management
interface.";

tag_solution = "Filter incoming traffic to this port.";

# History:
# 1.00, 11/21/07
# - Initial release

if (description)
    {
    script_id(80024);
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 16 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
    script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
    script_tag(name:"cvss_base", value:"0.0");
    script_tag(name:"risk_factor", value:"None");
    name="NetScaler web management interface detection";
    desc="
    Summary:
    " + tag_summary + "
    Solution:
    " + tag_solution;    summary="Detects NetScaler web management interface";
    family="Web Servers";
    script_name(name);
    script_description(desc);
    script_summary(summary);
    script_family(family);
    script_category(ACT_GATHER_INFO);
    script_copyright("This script is Copyright (c) 2007 nnposter");
    script_dependencies("find_service1.nasl","httpver.nasl");
    script_require_ports("Services/www",80);
    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "solution" , value : tag_solution);
      script_tag(name : "summary" , value : tag_summary);
    }
    script_xref(name : "URL" , value : "http://www.citrix.com/lang/English/ps2/index.asp");
    exit(0);
    }


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port=get_http_port(default:80);
if (!get_tcp_port_state(port)) exit(0);

resp=http_keepalive_send_recv(port:port,
                              data:http_get(item:"/index.html",port:port),
                              embedded:TRUE);
if (!resp) exit(0);

match1=egrep(pattern:"<title>Citrix Login</title>",string:resp,icase:TRUE);
match2=egrep(pattern:'action="/ws/login\\.pl"',string:resp,icase:TRUE);
if (!match1 || !match2) exit(0);

replace_kb_item(name:"www/netscaler",value:TRUE);
replace_kb_item(name:"www/netscaler/"+port,value:TRUE);
replace_kb_item(name:"Services/www/"+port+"/embedded",value:TRUE);

security_note(port);
