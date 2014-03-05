# OpenVAS Vulnerability Test
# $Id: zyxel_http_pwd.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Default web account on Zyxel
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
tag_summary = "The remote host is a Zyxel router with its default password set.

An attacker could connect to the web interface and reconfigure it.";

tag_solution = "Change the password immediately.";

if(description)
{
   script_id(17304);
   script_version("$Revision: 17 $");
   script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
   script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
   script_bugtraq_id(6671);
   script_tag(name:"cvss_base", value:"10.0");
   script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
   script_tag(name:"risk_factor", value:"Critical");
   
   script_cve_id("CVE-2001-1135", "CVE-1999-0571");
   
   name = "Default web account on Zyxel";
   script_name(name);
 
   desc = "
   Summary:
   " + tag_summary + "
   Solution:
   " + tag_solution;

   script_description(desc);
   summary = "Logs into the Zyxel web administration";
   script_summary(summary);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright("This script is Copyright (C) 2005 Michel Arboi");
   script_family( "Malware");
   script_dependencies("http_version.nasl");
   script_require_ports(80);
   if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
     script_tag(name : "solution" , value : tag_solution);
     script_tag(name : "summary" , value : tag_summary);
   }
   exit(0);
}

include("http_func.inc");
port = get_http_port(default:80);
if ( ! port || port != 80 ) exit(0);

banner = get_http_banner(port:port);
if ( "ZyXEL-RomPager" >!< banner ) exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);

# Do not use http_get, we do not want an Authorization header
send(socket: soc, data: 'GET / HTTP/1.0\r\n','Host: ' + get_host_name() + '\r\n\r\n');
h = http_recv_headers2(socket:soc);
if (h =~ "^HTTP/1\.[01] +401 ")
{ 
 http_close_socket(soc);
 soc = http_open_socket(port);
 if (! soc) exit(0);
 send(socket: soc, data: 'GET / HTTP/1.0\r\nAuthorization: Basic YWRtaW46MTIzNA==\r\n\r\n');
 h = http_recv_headers2(socket:soc);
 if (h =~ "^HTTP/1\.[01] +200 ") security_hole(port);
}

http_close_socket(soc);

