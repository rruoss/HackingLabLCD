# OpenVAS Vulnerability Test
# $Id: nortel_webadmin.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Nortel Web Management Default Username and Password (ro/ro)
#
# Authors:
# Noam Rathaus <noamr@beyondsecurity.com>
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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
tag_summary = "It is possible to access the remote network device's web management console
by providing it with a its default username and password (ro/ro). This username
can be also used when accessing the device via SSH, telnet, rlogin, etc.";

tag_solution = "Set a strong password for this account or disable it";

if(description)
{
 script_id(15716);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 name = "Nortel Web Management Default Username and Password (ro/ro)";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for the presence of default username and password";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 script_family("Default Accounts");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

debug = 0;

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

res = http_get_cache(item:"/", port:port);
if(res == NULL) exit(0);

# Sample response:
#
#<input type="hidden" name="encoded">
#<input type="hidden" name="nonce" value="
#0a7731a40000002a
#">
#<input type="submit" name="goto" value="Log On" onClick="encode()">


nonce = strstr(res, string('<input type="hidden" name="nonce" value="'));
nonce = strstr(nonce, string("\r\n"));
nonce -= string("\r\n");
nonce = nonce - strstr(nonce, string("\r\n"));
if(nonce)
{
 pre_md5 = string("ro:ro:", nonce);
 md5 = hexstr(MD5(pre_md5));
 req = string("POST / HTTP/1.1\r\n",
"Host: ", get_host_name(), ":", port, "\r\n",
"User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7) Gecko/20040928 Firefox/0.9.3\r\n",
"Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n",
"Accept-Language: en-us,en;q=0.5\r\n",
"Accept-Encoding: gzip,deflate\r\n",
"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
"Connection: close\r\n",
"Content-Type: application/x-www-form-urlencoded\r\n",
"Content-Length: ");

 content = string("encoded=ro%3A", md5, "&nonce=", nonce, "&goto=Log+On&URL=%2F");
 
 req = string(req, strlen(content), "\r\n\r\n",
              content);
 res2 = http_keepalive_send_recv(port:port, data:req, bodyonly:0);
 if(res2 == NULL) exit(0);
 if ((res2 >< "Set-Cookie: auth=") && (res2 >< "logo.html")) security_hole(port:port);
}
