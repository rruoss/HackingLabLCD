# OpenVAS Vulnerability Test
# $Id: horde_detect.nasl 41 2013-11-04 19:00:12Z jan $
# Description: Horde Detection
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
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
tag_summary = "This script detects whether the remote host is running Horde and
extracts version numbers and locations of any instances found. 

Horde is a PHP-based application framework from The Horde Project. 
See  http://www.horde.org/horde/  for more information.";

# NB: I define the script description here so I can later modify
#     it with the version number and install directory.
  desc = "
  Summary:
  " + tag_summary;


if (description) {
  script_id(15604);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 41 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 
  name = "Horde Detection";
  script_name(name);
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
 
  script_description(desc);
 
  summary = "Checks for the presence of Horde";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "General";
  script_family(family);

  script_dependencies("global_settings.nasl", "http_version.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.15604";
SCRIPT_DESC = "Horde Detection";

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);

if (debug_level) display("debug: looking for Horde on ", host, ":", port, ".\n");

# Search for Horde in a couple of different locations in addition to cgi_dirs().
dirs = make_list(cgi_dirs(), "/horde");

installs = 0;
foreach dir (dirs) {
  # Search for version number in a couple of different pages.
  files = make_list(
    "/services/help/?module=horde&show=about",
    "/docs/CHANGES", "/test.php", "/README", "/lib/version.phps",
    "/status.php3"
  );
  foreach file (files) {
    if (debug_level) display("debug: checking ", dir, file, "...\n");

    # Get the page.
    req = http_get(item:string(dir, file), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (res == NULL) exit(0);           # can't connect
    if (debug_level) display("debug: res =>>", res, "<<\n");

    if (egrep(string:res, pattern:"^HTTP/.\.. 200 ")) {
      # Specify pattern used to identify version string.
      # - version 3.x
      if (file =~ "^/services/help") {
        pat = ">This is Horde (.+)\.<";
      }
      # - version 2.x
      else if (file == "/docs/CHANGES") {
        pat = "^ *v(.+) *$";
      }
      #   nb: test.php available is itself a vulnerability but sometimes available.
      else if (file == "/test.php") {
        pat = "^ *<li>Horde: +(.+) *</li> *$";
      }
      #   nb: README is not guaranteed to be either available or accurate!!!
      else if (file == "/README") {
        pat = "^Version +(.+) *$";
      }
      #   nb: another security risk -- ability to view PHP source.
      else if (file == "/lib/version.phps") {
        pat = "HORDE_VERSION', '(.+)'";
      }
      # - version 1.x
      else if (file == "/status.php3") {
        pat = ">Horde, Version (.+)<";
      }
      # - someone updated files but forgot to add a pattern???
      else {
        if (debug_level) display("Don't know how to handle file '", file, "'!\n");
        exit(1);
      }

      # Get the version string.
      if (debug_level) display("debug: grepping results for =>>", pat, "<<\n");
      matches = egrep(pattern:pat, string:res);
      foreach match (split(matches)) {
        match = chomp(match);
        if (debug_level) display("debug: grepping >>", match, "<< for =>>", pat, "<<\n");
        ver = eregmatch(pattern:pat, string:match);
        if (ver == NULL) break;
        ver = ver[1];
        if (debug_level) display("debug: Horde version =>>", ver, "<<\n");

        # Success!
        tmp_version = string(ver, " under ", dir);
        set_kb_item(
          name:string("www/", port, "/horde"), 
          value:tmp_version);

        installations[dir] = ver;
        ++installs;

        ## build cpe and store it as host_detail
        cpe = build_cpe(value: tmp_version, exp:"^([0-9.]+)",base:"cpe:/a:horde:horde_groupware:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

        # nb: only worried about the first match.
        break;
      }
      # nb: if we found an installation, stop iterating through files.
      if (installs) break;
    }
  }
  # Scan for multiple installations only if "Thorough Tests" is checked.
  if (installs && !thorough_tests) break;
}

if(installs) {
  set_kb_item(name:"horde/installed",value:TRUE);
}  

# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    info = string("Horde ", ver, " was detected on the target under the path ", dir, ".");
  }
  else {
    info = string(
      "Multiple instances of Horde were detected on the target:\n",
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