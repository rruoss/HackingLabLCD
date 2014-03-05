###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpalbum_50437.nasl 13 2013-10-27 12:16:33Z jan $
#
# phpAlbum Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "phpAlbum is prone to an arbitrary-file-download vulnerability,
multiple cross-site scripting vulnerabilities, and multiple PHP code-
injection vulnerabilities because it fails to sufficiently sanitize
user-supplied data.

An attacker can exploit these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site, inject and execute arbitrary malicious PHP code, or download
arbitrary files within the context of the webserver process.

PhpAlbum 0.4.1.16 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103322);
 script_bugtraq_id(50437);
 script_cve_id("CVE-2011-4807", "CVE-2011-4806");
 script_version ("$Revision: 13 $");

 script_name("phpAlbum Multiple Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://secunia.com/advisories/44078");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50437");
 script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18045/");
 script_xref(name : "URL" , value : "http://www.phpalbum.net/dw");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-11-01 08:00:00 +0100 (Sun, 01 Nov 2011)");
 script_description(desc);
 script_summary("Determine if installed phpAlbum is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/phpalbum","/phpAlbum", "/phpAlbumnet",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/main.php"); 

  if(http_vuln_check(port:port, url:url, pattern:"<title>phpAlbum.net")) {

    url = string(dir, "/main.php?cmd=phpinfo");

    if(http_vuln_check(port:port, url:url, pattern:"<title>phpinfo")) {

      security_warning(port:port);
      exit(0);
   
    }
  }
}

exit(0);
