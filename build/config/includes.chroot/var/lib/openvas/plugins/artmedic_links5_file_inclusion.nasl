# OpenVAS Vulnerability Test
# $Id: artmedic_links5_file_inclusion.nasl 17 2013-10-27 14:01:43Z jan $
# Description: artmedic_links5 File Inclusion Vulnerability
#
# Authors:
# Noam Rathaus
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
tag_summary = "Artmedic Links a links generating PHP script,
has been found to contain an external file inclusion vulnerability.";

tag_impact = "The file inclusion vulnerability allows a remote attacker to include
external PHP files as if they were the server's own, this causing the
product to execute arbitrary code";

# From: Adam n30n Simuntis <n30n@satfilm.net.pl>
# Subject: artmedic_links5 PHP Script (include path) vuln
# Date: 25.6.2004 19:51

if(description)
{
 script_id(12289);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 
 name = "artmedic_links5 File Inclusion Vulnerability";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Impact:
 " + tag_impact;
 script_description(desc);
 
 summary = "Checks for artmedic_links5's PHP inclusion vulnerability";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "impact" , value : tag_impact);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

debug = 0;
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 req = string(dir,"/artmedic_links5/index.php?id=index.php");
 req = http_get(item:req, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);

 if ('require("linksscript/include.php");' >< buf ) 
	{
	security_hole(port);
	exit(0);
	}
}

