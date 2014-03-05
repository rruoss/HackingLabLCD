# OpenVAS Vulnerability Test
# $Id: netscaler_web_cookie_info.nasl 16 2013-10-27 13:09:52Z jan $
# Description: NetScaler web management cookie information
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
tag_summary = "The remote web server is prone to an information disclosure attack. 

Description :

It is possible to extract information about the remote Citrix
NetScaler appliance obtained from the web management interface's
session cookie, including the appliance's main IP address and software
version.";

# History:
# 1.00, 11/21/07
# - Initial release

    desc="
    Summary:
    " + tag_summary;


if (description)
    {
    script_id(80023);
    script_version("$Revision: 16 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
    script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
    script_tag(name:"cvss_base", value:"5.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
    script_tag(name:"risk_factor", value:"Medium");
    name="NetScaler web management cookie information";
    summary="Reports NetScaler web cookie information";
    script_name(name);
    script_description(desc);
    script_summary(summary);
    script_family("Web Servers");
    script_category(ACT_GATHER_INFO);
    script_cve_id("CVE-2007-6193");
    script_xref(name:"OSVDB", value:"44155");
    script_copyright("This script is Copyright (c) 2007 nnposter");
    script_dependencies("netscaler_web_login.nasl");
    script_require_keys("www/netscaler");
    script_require_ports("Services/www",80);
    script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/484182/100/0/threaded");
    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
    }


if (!get_kb_item("www/netscaler")) exit(0);
if (!get_kb_item("http/password")) exit(0);


include("misc_func.inc");
include("url_func.inc");
include("http_func.inc");


function cookie_extract (cookie,parm)
{
local_var match;
match=eregmatch(string:cookie,pattern:' '+parm+'=([^; \r\n]*)',icase:TRUE);
if (isnull(match)) return;
return match[1];
}


port=get_http_port(default:80);
if (!get_kb_item("www/netscaler/"+port)) exit(0);
cookie=get_kb_item("/tmp/http/auth/"+port);
if (!cookie) exit(0);

found="";

nsip=cookie_extract(cookie:cookie,parm:"domain");
if (nsip && nsip+"."=~"^([0-9]{1,3}\.){4}$")
    found+='Main IP address  : '+nsip+'\n';

nsversion=urldecode(estr:cookie_extract(cookie:cookie,parm:"nsversion"));
if (nsversion)
    {
    replace_kb_item(name:"www/netscaler/"+port+"/version",
                           value:nsversion);
    found+='Software version : '+nsversion+'\n';
    }

if (!found) exit(0);

report = string(
    desc,
    "\n\n",
    "Plugin output :\n",
    "\n",
    "It was possible to determine the following information about the\n",
    "Citrix NetScaler appliance by examining the web management cookie :\n",
    "\n",
    found
);
security_warning(port:port,data:report);
