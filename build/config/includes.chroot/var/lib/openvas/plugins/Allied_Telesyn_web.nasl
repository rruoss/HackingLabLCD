# OpenVAS Vulnerability Test
# $Id: Allied_Telesyn_web.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Allied Telesyn Router/Switch Web interface found with default password
#
# Authors:
# Charles Thier <cthier@thethiers.net>
# This script was based off of Renaud Deraison's script 
# 11522 Linksys Router default password script.
#
# Copyright:
# Copyright (C) 2005 Charles Thier
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
tag_summary = "The Allied Telesyn Router/Switch has the default password set.

The attacker could use this default password to gain remote access
to your switch or router.  This password could also be potentially used to
gain other sensitive information about your network from the device.";

tag_solution = "Connect to this Router/Switch and change the default password.";

if(description)
{
    script_id(18413);
    script_version("$Revision: 17 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
    script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"4.6");
    script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name:"risk_factor", value:"Medium");
    script_cve_id("CVE-1999-0508");
    name = "Allied Telesyn Router/Switch Web interface found with default password";
    script_name(name);
 
   desc = "
    Summary:
    " + tag_summary + "
    Solution:
    " + tag_solution;

   script_description(desc);
 
   summary = "Logs into Allied Telesyn routers and switches Web interface with default password";
   script_summary(summary);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright("This script is Copyright (C) 2005 Charles Thier");
   script_family("Default Accounts");
   script_dependencies("http_version.nasl");
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
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner (port:port);
if (!banner || ("Server: ATR-HTTP-Server" >!< banner))
  exit(0);

res = http_get_cache(item:"/", port:port);
if ( res == NULL ) exit(0);
if ( egrep ( pattern:"^HTTP/.* 401 .*", string:res ) )
{
 req -= string("\r\n\r\n");
#  Credentials manager:friend
 req += string("\r\nAuthorization: Basic bWFuYWdlcjpmcmllbmQ=\r\n\r\n");
 res = http_keepalive_send_recv(port:port, data:req);
 if (res == NULL ) exit(0);
 if ( egrep ( pattern:"^HTTP/.* 200 .*", string:res) )
	security_warning(port);
}

