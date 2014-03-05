# OpenVAS Vulnerability Test
# $Id: DDI_Compaq_Mgmt_Proxy.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Compaq Web Based Management Agent Proxy Vulnerability
#
# Authors:
# H D Moore <hdmoore@digitaldefense.net>
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
tag_summary = "This host is running the Compaq Web Management 
Agent. This service can be used as a HTTP 
proxy. An attacker can use this to bypass 
firewall rules or hide the source of web-based 
attacks.";

tag_solution = "Due to the information leak associated
with this service, we recommend that you disable 
the Compaq Management Agent or filter access to 
TCP ports 2301 and 280.

If this service is required, installing the 
appropriate upgrade from Compaq will fix this 
issue. The software update for your operating 
system and hardware can be found via Compaq's 
support download page: 
http://www.compaq.com/support/files/server/us/index.html

For more information, please see the vendor advisory at: 
http://www.compaq.com/products/servers/management/SSRT0758.html";


if(description)
{
 script_id(10963);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2001-0374");
 name = "Compaq Web Based Management Agent Proxy Vulnerability";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "Compaq Web Based Management Agent Proxy Vulnerability";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2002 Digital Defense Inc.");
 family = "General";
 script_family(family);

 script_dependencies("find_service.nasl", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 2301);
 script_require_keys("www/compaq");
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
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:2301);

foreach port (ports)
{
    soc = http_open_socket(port);
    if (soc)
    {
        req = string("GET http://127.0.0.1:2301/ HTTP/1.0\r\n\r\n");
        send(socket:soc, data:req);
        buf = http_recv(socket:soc);
        http_close_socket(soc);
        
        if ("Compaq WBEM Device Home" >< buf)
        {
            security_hole(port:port);
        }
    }
}
