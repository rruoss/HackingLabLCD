# OpenVAS Vulnerability Test
# $Id: uebimiau_session_disclosure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Uebimiau Session Directory Disclosure
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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
tag_summary = "UebiMiau is a simple and cross-plataform POP3/IMAP mail
reader written in PHP.

Uebimiau in default installation create one temporary folder 
to store 'sessions' and other files. This folder is defined 
in 'inc/config.php' as './database/'.

If the web administrator don't change this folder, an attacker
can exploit this using the follow request:
http://server-target/database/_sessions/

Solutions:
1) Insert index.php in each directory of the Uebimiau

2) Set variable $temporary_directory to a directory 
not public and with restricted access, set permission
as read only to 'web server user' for each files in
$temporary_directory.

3) Set open_basedir in httpd.conf to yours clients follow  
the model below:

<Directory /server-target/public_html>
 php_admin_value open_basedir
 /server-target/public_html
</Directory>";

# ITTS ADVISORE 01/05 - Uebimiau <= 2.7.2 Multiples Vulnerabilities
# Martin Fallon <mar_fallon@yahoo.com.br>
# 2005-01-27 14:09

if(description)
{
 script_id(16279);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "Uebimiau Session Directory Disclosure";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Checks for the presence of sessions directory of UebiMiau";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "httpver.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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

function check(loc)
{
 req = http_get(item:string(loc, "/database/_sessions/"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if (( "Parent Directory" >< r) && ("/database/_sessions" >< r))
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir (make_list("", "/uebimiau-2.7.2", "/mailpop", "/webmail", cgi_dirs()))
{
 check(loc:dir);
}

