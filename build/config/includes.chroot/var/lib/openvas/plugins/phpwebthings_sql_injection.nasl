# OpenVAS Vulnerability Test
# $Id: phpwebthings_sql_injection.nasl 17 2013-10-27 14:01:43Z jan $
# Description: phpWebThings forum Parameter SQL Injection Vulnerabilities
#
# Authors:
# Ferdy Riphagen <f[dot]riphagen[at]nsec[dot]nl>
#
# Copyright:
# Copyright (C) 2005 Ferdy Riphagen
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
tag_summary = "The remote web server contains a PHP script that is prone to SQL
injection attacks. 

Description :

The remote host is running the phpWebThings application framework. 

The version of phpWebThings installed on the remote host does not
properly sanitize user input in the 'forum' and 'msg' parameters of
'forum.php' script before using it in database queries.  An attacker
can exploit this vulnerability to display the usernames and passwords
(md5 hash) from the website and then use this information to gain
administrative access to the affected application.";

tag_solution = "Apply the phpWebthings 1.4 forum patch referenced in the third URL
above.";

if (description) {
script_id(20170);
script_version("$Revision: 17 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"risk_factor", value:"High");

script_cve_id("CVE-2005-3585", "CVE-2005-4218");
script_bugtraq_id(15276, 15465);
script_xref(name:"OSVDB", value:"20441");


name = "phpWebThings forum Parameter SQL Injection Vulnerabilities";
script_name(name);

desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;script_description(desc);

summary = "Check if phpWebThings is vulnerable to SQL Injection attacks";
script_summary(summary);

script_category(ACT_ATTACK);
script_family("Web application abuses");

script_copyright("This script is Copyright (C) 2005 Ferdy Riphagen");

script_dependencies("http_version.nasl");
script_require_ports("Services/www", 80);
script_exclude_keys("Settings/disable_cgi_scanning");

if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
}
script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2005-11/0057.html");
script_xref(name : "URL" , value : "http://retrogod.altervista.org/phpwebth14_xpl.html");
script_xref(name : "URL" , value : "http://www.ojvweb.nl/download.php?file=64&amp;cat=17&amp;subref=10");
exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = make_list("/phpwebthings", "/webthings", "/phpwt", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  exploit = "-1 UNION SELECT null,123456,null,null,null,null/*";
  req = http_get(item:string(dir, "/forum.php?forum=", urlencode(str:exploit)), port:port);
  recv = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if(recv == NULL)exit(0);

  if (
    string('<input type="hidden" value="', exploit, '" name="sforum"') >< recv &&
    egrep(pattern:"created with <a href=[^>]+.*>phpWebThings", string:recv)
  ) {
   security_hole(port);
   exit(0);
  }
}