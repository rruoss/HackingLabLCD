# OpenVAS Vulnerability Test
# $Id: mailman_detect.nasl 41 2013-11-04 19:00:12Z jan $
# Description: Mailman Detection
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
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
tag_summary = "This script detects whether the remote host is running Mailman and
extracts version numbers and locations of any instances found. 

Mailman is a Python-based mailing list management package from the GNU
Project.  See http://www.list.org/ for more information.";
 
# NB: I define the script description here so I can later modify
#     it with the version number and install directory.
  desc = "
  Summary:
  " + tag_summary;


if (description) {
  script_id(16338);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 41 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");

  name = "Mailman Detection";
  script_name(name);
 
  script_description(desc);
 
  summary = "Checks for the presence of Mailman";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 George A. Theall");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("global_settings.nasl", "http_version.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);
debug_print("looking for Mailman on port ", port, ".");

# Search for Mailman's listinfo page.
dirs = make_list("/mailman", cgi_dirs());
installs = 0;
foreach dir (dirs) {
  listinfo = string(dir, "/listinfo");
  debug_print("testing '", listinfo, "'.");
  if (dir == "") dir = "/";

  # Get the page.
  req = http_get(item:listinfo, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);           # can't connect
  debug_print("result = >>", res, "<<.");

  # Find the version number. It will be in a line such as
  #   <td><img src="/icons/mailman.jpg" alt="Delivered by Mailman" border=0><br>version 2.1.5</td>
  pat = "alt=.Delivered by Mailman..+>version ([^<]+)";
  debug_print("grepping results for =>>", pat, "<<.");
  matches = egrep(pattern:pat, string:res);
  foreach match (split(matches)) {
    match = chomp(match);
    debug_print("grepping >>", match, "<< for =>>", pat, "<<.");
    ver = eregmatch(pattern:pat, string:match);
    if (ver == NULL) break;
    ver = ver[1];
    debug_print("Mailman version =>>", ver, "<<.");

    # Success!
    set_kb_item(
      name:string("www/", port, "/Mailman"), 
      value:string(ver, " under ", dir)
    );
    installations[dir] = ver;
    ++installs;

    # nb: only worried about the first match.
    break;
  }
  # Scan for multiple installations only if "Thorough Tests" is checked.
  if (installs && !thorough_tests) break;
}

# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    info = string("Mailman ", ver, " was detected on the remote host under the path ", dir, ".");
  }
  else {
    info = string(
      "Multiple instances of Mailman were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  desc = ereg_replace(
    string:desc,
    pattern:"This script[^\.]+\.", 
    replace:info
  );
  security_note(port:port, data:desc);
}
