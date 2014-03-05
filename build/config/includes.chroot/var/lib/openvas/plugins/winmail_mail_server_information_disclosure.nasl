# OpenVAS Vulnerability Test
# $Id: winmail_mail_server_information_disclosure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Winmail Mail Server Information Disclosure
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
tag_summary = "The remote host is running Winmail Server.

Winmail Server is an enterprise class mail server software system
offering a robust feature set, including extensive security
measures. Winmail Server supports SMTP, POP3, IMAP, Webmail, LDAP,
multiple domains, SMTP authentication, spam protection, anti-virus
protection, SSL/TLS security, Network Storage, remote access,
Web-based administration, and a wide array of standard email options
such as filtering, signatures, real-time monitoring, archiving,
and public email folders. 

Three scripts that come with the program (chgpwd.php, domain.php and user.php) 
allow a remote attacker to disclose sensitive information about the remote host.";

tag_solution = "Upgrade to the latest version of this software";

if(description)
{
 script_id(16042);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_xref(name:"OSVDB", value:"12336");
 script_xref(name:"OSVDB", value:"12337");
 script_xref(name:"OSVDB", value:"12338");
 
 name = "Winmail Mail Server Information Disclosure";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for the presence of an Information Disclosure in Winmail Mail Server";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
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

debug = 0;

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 if (debug) { display("loc: ", loc, "\n"); }
 req = http_get(item:string(loc, "/chgpwd.php"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if (debug) { display("r: [", r, "]\n"); }
 if(("Call to a member function on a non-object in" >< r) && ("Fatal error" >< r) &&
    ("Winmail" >< r) && ("admin" >< r) && ("chgpwd.php" >< r))
 {
 	security_warning(port);
	exit(0);
 }
}

dirs = make_list(cgi_dirs(), "/admin/");

foreach dir (dirs)
{
 check(loc:dir);
}

