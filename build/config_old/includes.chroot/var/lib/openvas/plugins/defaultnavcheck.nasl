# OpenVAS Vulnerability Test
# $Id: defaultnavcheck.nasl 17 2013-10-27 14:01:43Z jan $
# Description: DefaultNav checker
#
# Authors:
# Hemil Shah
#
# Copyright:
# Copyright (C) 2000 - 2004 Net-Square Solutions Pvt Ltd.
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
tag_summary = "This plugin checks for DefaultNav vulnerabilities on the remote web server

For more information, see:
http://www.nextgenss.com/advisories/defaultnav.txt";

# Desc: This script will check for the DefaultNav vuln working on remote web server.

if(description)
{
	script_id(12247);
	script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"0.0");
    script_tag(name:"risk_factor", value:"None");
 	name = "DefaultNav checker";
 	script_name(name);
  
	desc = "
 Summary:
 " + tag_summary;

	script_description(desc);

 	summary = "DefaultNav checker";
	script_summary(summary);

	script_category(ACT_ATTACK);

	script_copyright("This script is Copyright (C) 2004 Net-Square Solutions Pvt Ltd.");
	family = "General";
	script_family(family);

	script_dependencies("find_service.nasl");
	script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
	exit(0);
}

# start script
include("http_func.inc");
include("http_keepalive.inc");


exit(0); # Broken

port = get_http_port(default:80);

if(! get_port_state(port))
    exit(0);

if ( get_kb_item("www/no404/" + port ) ) exit(0);

DEBUG = 0;


dirs[0] = "/%24DefaultNav";
dirs[1] = "/%24defaultNav";
dirs[2] = "/%24%64*efaultNav";
dirs[3] = "/%24%44*efaultnav";
dirs[4] = "/$defaultNav";
dirs[5] = "/$DefaultNav";
dirs[6] = "/$%64efaultNav";
dirs[7] = "/$%44efaultNav";

report = string("The DefaultNav request is enabled on the remote host\n");



nsfName = "/names.nsf";

for (i=0; dirs[i]; i++)
{   
	res = http_keepalive_send_recv(port:port, data:http_get(item:string(nsfName, dirs[i], "/"), port:port));

	if ( res == NULL ) exit(0);
       
        if(ereg(pattern:"HTTP/1.[01] 200", string:res) && res!=customres)
        {
	    report = report + string("specifically, the request for ", nsfName, dirs[i], "/ is\n");
            report = report + string("capable of remotely compromising the integrity of the\n");
	    report = report + string("system.  For more information, please see:\n");
	    report = report + string("http://www.nextgenss.com/advisories/defaultnav.txt\n");
            security_hole(port:port, data:report);            
            exit(0);
        }
}


