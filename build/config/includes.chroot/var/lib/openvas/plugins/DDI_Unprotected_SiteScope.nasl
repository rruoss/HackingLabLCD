# OpenVAS Vulnerability Test
# $Id: DDI_Unprotected_SiteScope.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Unprotected SiteScope Service
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
tag_summary = "The SiteScope web service has no password set. An attacker
who can connect to this server could view usernames and
passwords stored in the preferences section or reconfigure
the service.";

tag_solution = "Make sure that a password is set in the configuration
for this service. Depending on where this server is located, 
you may want to restrict access by IP address in addition to 
username.";

if(description)
{
    script_id(10778);
    script_version("$Revision: 17 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
    script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"4.6");
    script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name:"risk_factor", value:"Medium");
    script_cve_id("CVE-1999-0508");
    name = "Unprotected SiteScope Service";
    script_name(name);


    desc = "
    Summary:
    " + tag_summary + "
    Solution:
    " + tag_solution;

    script_description(desc);


    summary = "Unprotected SiteScope Service";
    script_summary(summary);


    script_category(ACT_ATTACK);

    script_copyright("This script is Copyright (C) 2001 Digital Defense Inc.");

    family = "Web application abuses";
    script_family(family);
    script_dependencies("find_service.nasl", "http_version.nasl");
    script_require_ports("Services/www", 8888);
    
    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "solution" , value : tag_solution);
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

function sendrequest (request, port)
{
    
    reply = http_keepalive_send_recv(port: port, data:request);
    if ( reply == NULL ) exit(0);
    else return reply;
}

#
# The script code starts here
#


ports = add_port_in_list(list:get_kb_list("Services/www"), port:8888);
foreach port (ports)
{
 req = http_get(item:"/SiteScope/cgi/go.exe/SiteScope?page=eventLog&machine=&logName=System&account=administrator", port:port);
 reply = sendrequest(request:req, port:port);

 if ("Event Log" >< reply)
 {
    security_warning(port:port);
 }
}
