# OpenVAS Vulnerability Test
# $Id: horde_test_disclosure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Horde and IMP test disclosure
#
# Authors:
# Sverre H. Huseby <shh@thathost.com>
#
# Copyright:
# Copyright (C) 2004 Sverre H. Huseby
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
tag_summary = "The remote server is running Horde and/or IMP with test scripts
available from the outside.  The scripts may leak server-side
information that is valuable to an attacker.";

tag_solution = "test.php and imp/test.php should be deleted,
or they should be made unreadable by the web server.";

if(description)
{
  script_id(11617);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");

  name = "Horde and IMP test disclosure";
  script_name(name);

  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
  script_description(desc);

  summary = "Checks if test.php is available in Horde or IMP";

  script_summary(summary);

  script_category(ACT_ATTACK);

  script_copyright("Copyright 2004 (C) Sverre H. Huseby");
  family = "Web application abuses";
  script_family(family);

  script_dependencies("horde_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("horde/installed");

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

files = make_list(
  "/test.php", "/test.php3",
  "/imp/test.php", "/imp/test.php3"
);

# Test an install.
install = get_kb_item(string("www/", port, "/horde"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  d = matches[2];

  foreach f (files) {
    req = http_get(item:string(d, f), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if (res == NULL)
      exit(0);

    if ('PHP Version' >< res
        && ('Horde Version' >< res || 'IMP Version' >< res)) {
      security_warning(port);
      exit(0);
    }
  }
}
