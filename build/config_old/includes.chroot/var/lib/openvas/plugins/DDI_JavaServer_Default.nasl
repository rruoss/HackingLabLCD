# OpenVAS Vulnerability Test
# $Id: DDI_JavaServer_Default.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Sun JavaServer Default Admin Password
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
tag_summary = "This host is running the Sun JavaServer.  This 
server has the default username and password 
of admin.  An attacker can use this to gain 
complete control over the web server 
configuration and possibly execute commands.";

tag_solution = "Set the web administration interface to require a
            complex password.  For more information please 
            consult the documentation located in the /system/ 
            directory of the web server.";

if(description)
{
 script_id(10995);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-1999-0508");

 name = "Sun JavaServer Default Admin Password";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);

 summary = "Sun JavaServer Default Admin Password";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2002 Digital Defense Inc.");
 family = "General";
 script_family(family);

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 9090);
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


req = "/servlet/admin?category=server&method=listAll&Authorization=Digest+";
req = req + "username%3D%22admin%22%2C+response%3D%22ae9f86d6beaa3f9ecb9a5b7e072a4138%22%2C+";
req = req + "nonce%3D%222b089ba7985a883ab2eddcd3539a6c94%22%2C+realm%3D%22adminRealm%22%2C+";
req = req + "uri%3D%22%2Fservlet%2Fadmin%22&service=";

ports = add_port_in_list(list:get_kb_list("Services/www"), port:9090);

foreach port (ports)
{
    if ( ! get_kb_item("Services/www/" + port + "/embedded") )
    {
    soc = http_open_socket(port);
    if (soc)
    {
        req = string("GET ", req, " HTTP/1.0\r\n\r\n");
        send(socket:soc, data:req);
        buf = http_recv(socket:soc);
        http_close_socket(soc);
        if (("server.javawebserver.serviceAdmin" >< buf))
        {
            security_warning(port:port);
        }
    }
  }
}
