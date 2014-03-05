# OpenVAS Vulnerability Test
# $Id: zeroblog_xss.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Zeroblog <= 1.2a Cross-Site Scripting Vulnerability
#
# Authors:
# Ferdy Riphagen <f(dot)riphagen(at)nsec(dot)nl>
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
tag_summary = "The remote host contains a PHP script that is vulnerable to cross-site
scripting attacks.

Description :

The remote host appears to be running ZeroBlog.

A vulnerability was identified in Zeroblog, which may be exploited by
remote attackers to inject script code.

ZeroBlog does not properly sanitize user input in the 'threadID', 'replyID' and 'albumID' parameters.";

tag_solution = "Unknown at this time.";

if (description) {
script_id(200003);
script_version("$Revision: 16 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
script_tag(name:"risk_factor", value:"Medium");

script_tag(name:"cvss_base", value:"4.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2005-3264");
 script_bugtraq_id(15078);

name = "Zeroblog <= 1.2a Cross-Site Scripting Vulnerability";
script_name(name);

desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;script_description(desc);

summary = "Check if Zeroblog is vulnerable to cross-site scripting attacks.";
script_summary(summary);

script_category(ACT_GATHER_INFO);
script_family("Web application abuses");

script_copyright("This script is Copyright (C) 2005 Ferdy Riphagen");

script_dependencies("http_version.nasl");
script_require_ports("Services/www", 80);

if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
}
exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

xss = "'<IFRAME SRC=javascript:alert(%27XSS DETECTED BY OpenVAS%27)></IFRAME>";
exss = urlencode(str:xss);

if (thorough_tests) dirs = make_list("/zeroblog", "/", "/blog", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 res = http_get_cache(item:string(dir, "/thread.php"), port:port);
 if (res == NULL) exit(0);

 if (egrep(pattern:">.*Copyright.*(C).*ZeroCom.*computers", string:res))
 {
  req = http_get(item:string(dir, "/thread.php?threadID=", exss), port:port);

  recv = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if(recv == NULL)exit(0);

  if(xss >< recv)
  {
   security_warning(port);
   exit(0);
  }
 }
}
