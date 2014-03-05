# OpenVAS Vulnerability Test
# $Id: my_little_forum_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: My Little Forum XSS Vulnerability
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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
tag_summary = "The remote host is running 'My Little Forum', a free CGI suite to manage
discussion forums.

This PHP/MySQL based forum suffers from a Cross Site Scripting vulnerability.
This can be exploited by including arbitrary HTML or even JavaScript code in
the parameters (forum_contact, category and page), which will be executed in
user's browser session when viewed.";

# From: David S. Ferreira [iamroot@systemsecure.org]
# Subject: My Little Forum XSS Attack
# Date: Tuesday 23/12/2003 08:20

if(description)
{

  script_id(11960);
  script_version("$Revision: 17 $");
  script_bugtraq_id(9286);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  name = "My Little Forum XSS Vulnerability";
  script_name(name);

  desc = "
  Summary:
  " + tag_summary;

  script_xref(name : "URL" , value : "http://secunia.com/advisories/10489/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/14066");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1008545");
  script_xref(name : "URL" , value : "http://www.os2world.com/content/view/12704/79/");

  script_description(desc);

  summary = "Detect My Little Forum XSS";
  script_summary(summary);

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");

  family = "Web application abuses";
  script_family(family);
  script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if (!get_port_state(port) ) exit(0);
if (!can_host_php(port:port)) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);


quote = raw_string(0x22);

function check_dir(path)
{
 req = http_get(item:string(path, "/forum/email.php?forum_contact=", quote, "><script>foo</script>"), port:port);

 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);

 if ( res == NULL ) exit(0);
 find = "<script>foo</script>";

 if ( find >< res ) 
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check_dir(path:dir);
}
