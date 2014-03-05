# OpenVAS Vulnerability Test
# $Id: openwebmail_logindomain_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Open WebMail Logindomain Parameter Cross-Site Scripting Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2005 George A. Theall
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
tag_summary = "The remote webmail server is affected by a cross-site scripting flaw.

Description :

The remote host is running at least one instance of Open WebMail that
fails to sufficiently validate user input supplied to the 'logindomain'
parameter.  This failure enables an attacker to run arbitrary script
code in the context of a user's web browser.";

tag_solution = "Upgrade to Open WebMail version 2.50 20040212 or later.";

if (description) {
  script_id(16463);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2005-0445");
  script_bugtraq_id(12547);
  script_xref(name:"OSVDB", value:"13788");

  name = "Open WebMail Logindomain Parameter Cross-Site Scripting Vulnerability";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;  script_description(desc);
 
  summary = "Checks for logindomain parameter cross-site scripting vulnerability in Open WebMail";
  script_summary(summary);
 
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 George A. Theall");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("openwebmail_detect.nasl");
  script_require_ports("Services/www", 80);

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://openwebmail.org/openwebmail/download/cert/advisories/SA-05:01.txt");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

# We test whether the hole exists by trying to echo magic (urlencoded
# as alt_magic for http) and checking whether we get it back.
magic = "logindomain xss vulnerability";
alt_magic = str_replace(string:magic, find:" ", replace:"%20");


# Test an install.
install = get_kb_item(string("www/", port, "/openwebmail"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  url = string(
    dir, 
    "/openwebmail.pl?logindomain=%22%20/%3E%3Cscript%3Ewindow.alert('",
    alt_magic,
    "')%3C/script%3E"
  );
  debug_print("retrieving '", url, "'.");
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) exit(0);           # can't connect
  debug_print("res =>>", res, "<<");

  if (egrep(string:res, pattern:magic)) {
    security_warning(port);
    exit(0);
  }
}
