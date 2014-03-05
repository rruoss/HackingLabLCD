# OpenVAS Vulnerability Test
# $Id: cobalt_cube_webmail_dir_trav.nasl 17 2013-10-27 14:01:43Z jan $
# Description: readmsg.php detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added link to the Bugtraq message archive
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
tag_summary = "/base/webmail/readmsg.php was detected.
Some versions of this CGI allow remote users to read local
files with the permission of the web server.
Note that if the user has a shell access, this kind of attack is 
not interesting.

*** OpenVAS just checked the presence of this file 
*** but did not try to exploit the flaw.";

tag_solution = "get a newer software from Cobalt

Reference : http://online.securityfocus.com/archive/1/195165";


# References:
# Date:  Thu, 05 Jul 2001 03:41:50 -0400
# From: "KF" <dotslash@snosoft.com>
# To: bugtraq@securityfocus.com, recon@snosoft.com
# Subject: Cobalt Cube Webmail directory traversal

if(description)
{
 script_id(11073);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2001-1408");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "readmsg.php detection";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Checks for the presence of Cobal Cube webmail";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 444);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

if ( ! get_port_state(port) ) exit(0);
if ( ! can_host_php(port:port) ) exit(0);

res = is_cgi_installed_ka(item:"/base/webmail/readmsg.php", port:port);
if( res ) security_warning(port);

# The attack is:
# http://YOURCOBALTBOX:444/base/webmail/readmsg.php?mailbox=../../../../../../../../../../../../../../etc/passwd&id=1
