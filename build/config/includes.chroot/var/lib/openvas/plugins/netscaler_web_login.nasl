# OpenVAS Vulnerability Test
# $Id: netscaler_web_login.nasl 16 2013-10-27 13:09:52Z jan $
# Description: NetScaler web management login
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
tag_summary = "It is possible to log into the remote web management interface. 

Description :

OpenVAS successfully logged into the remote Citrix NetScaler web
management interface using the supplied credentials and stored the
authentication cookie for later use.";

# History:
# 1.00, 11/21/07
# - Initial release

if (description)
    {
    script_id(80025);
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 16 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
    script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
    script_tag(name:"cvss_base", value:"0.0");
    script_tag(name:"risk_factor", value:"None");
    name="NetScaler web management login";
    desc="
    Summary:
    " + tag_summary;    summary="Logs into NetScaler web management interface";
    family="Settings";
    script_name(name);
    script_description(desc);
    script_summary(summary);
    script_family(family);
    script_category(ACT_GATHER_INFO);
    script_copyright("This script is Copyright (c) 2007 nnposter");
    script_dependencies("logins.nasl","netscaler_web_detect.nasl");
    script_require_keys("www/netscaler","http/login");
    script_require_ports("Services/www",80);
    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
    }


if (!get_kb_item("www/netscaler")) exit(0);
if (!get_kb_item("http/login"))    exit(0);


include("url_func.inc");
include("http_func.inc");
include("http_keepalive.inc");


port=get_http_port(default:80);
if (!get_tcp_port_state(port) || !get_kb_item("www/netscaler/"+port))
    exit(0);

url="/ws/login.pl?"
    + "username="+urlencode(str:get_kb_item("http/login"))
    +"&password="+urlencode(str:get_kb_item("http/password"))
    +"&appselect=stat";

resp=http_keepalive_send_recv(port:port,
                              data:http_get(item:url,port:port),
                              embedded:TRUE);
if (!resp) exit(0);

cookie=egrep(pattern:"^Set-Cookie:",string:resp,icase:TRUE);
if (!cookie) exit(0);

cookie=ereg_replace(string:cookie,pattern:'^Set-',replace:" ",icase:TRUE);
cookie=ereg_replace(string:cookie,pattern:';[^\r\n]*',replace:";",icase:TRUE);
cookie=ereg_replace(string:cookie,pattern:'\r\nSet-Cookie: *',replace:" ",icase:TRUE);
cookie=ereg_replace(string:cookie,pattern:'; *(\r\n)',replace:"\1",icase:TRUE);
if (cookie!~" ns1=.* ns2=") exit(0);

set_kb_item(name:"/tmp/http/auth/"+port,value:cookie);
security_note(port);
