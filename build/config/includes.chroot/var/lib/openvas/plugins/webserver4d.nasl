# OpenVAS Vulnerability Test
# $Id: webserver4d.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Webserver 4D Cleartext Passwords
#
# Authors:
# Jason Lidow <jason@brandx.net>
#
# Copyright:
# Copyright (C) 2002 Jason Lidow <jason@brandx.net>
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
tag_solution = "Contact http://www.mdg.com for an update.";

tag_summary = "The remote host is running Webserver 4D 3.6 or lower.
  
Version 3.6 of this service stores all usernames and passwords in cleartext. 
File: C:\Program Files\MDG\Web Server 4D 3.6.0\Ws4d.4DD

A local attacker may use this flaw to gain unauthorized privileges
on this host.";


# The vulnerability was originally discovered by ts@securityoffice.net 

if(description)
{
        script_id(11151);
        script_version("$Revision: 17 $");
        script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
        script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
        script_bugtraq_id(5803);
	script_cve_id("CVE-2002-1521");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
        script_name("Webserver 4D Cleartext Passwords");


    desc = "
    Summary:
    " + tag_summary + "
        Solution:
        " + tag_solution;

        script_description(desc);

        script_summary("Checks for Webserver 4D");


        script_category(ACT_GATHER_INFO);


        script_copyright("This script is Copyright (C) 2002 Jason Lidow <jason@brandx.net>");
        script_family("Web Servers");
        script_dependencies("find_service.nasl", "httpver.nasl", "no404.nasl");
        script_require_ports("Services/www", 80);
        if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
          script_tag(name : "solution" , value : tag_solution);
          script_tag(name : "summary" , value : tag_summary);
        }
        exit(0);
}


include("http_func.inc");
port = get_http_port(default:80);


banner = get_http_banner(port:port);


poprocks = egrep(pattern:"^Server.*", string: banner);
if(banner)
{
        if("Web_Server_4D" >< banner) 
	{
                yo = string("The following banner was received: ", poprocks, "\n\nVersion 3.6 and lower of Webserver 4D stores all usernames and passwords in cleartext.\n\nFile: C:\\Program Files\\MDG\\Web Server 4D 3.6.0\\Ws4d.4DD\n\nRisk Factor: Low\nSolution: Contact http://www.mdg.com for an update.");
                security_warning(port:port, data:yo);
 	}
}
