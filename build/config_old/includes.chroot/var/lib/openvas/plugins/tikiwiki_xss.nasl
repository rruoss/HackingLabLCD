# OpenVAS Vulnerability Test
# $Id: tikiwiki_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: TikiWiki tiki-error.php XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
tag_summary = "The remote host is running TikiWiki, a content management 
system written in PHP.

The remote version of this software is vulnerable to cross-site 
scripting attacks in tiki-error.php script due to a lack of user 
input sanitization.";

tag_solution = "Upgraded to version 1.7.8 or newer.";

# Ref: Florian Hengartner <hengartnerf@users.sourceforge.net>

if(description)
{
  script_id(15709);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(14121);
  script_xref(name:"OSVDB", value:7449);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N"); 
  script_tag(name:"risk_factor", value:"Medium");
  script_name("TikiWiki tiki-error.php XSS");

 
 desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);

  script_summary("Checks TikiWiki version");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www");
 script_exclude_keys("Settings/disable_cgi_scanning");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

#now the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 req = http_get(item: loc + "/tiki-index.php", port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if( "This is Tiki v" >< r && egrep(pattern:"This is Tiki v(0\.|1\.[0-6]\.|1\.7\.[0-7][^0-9])", string:r) )
 {
 	security_warning(port);
	exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}
