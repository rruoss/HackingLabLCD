###############################################################################
# OpenVAS Vulnerability Test
# $Id: Turnkey_eBook_store_xss_34324.nasl 15 2013-10-27 12:49:54Z jan $
#
# Turnkey eBook Store 'keywords' Parameter Cross Site Scripting
# Vulnerability
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
tag_summary = "Turnkey eBook Store is prone to a cross-site scripting vulnerability.

  An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site and to steal cookie-based authentication credentials.

  Turnkey eBook Store 1.1 is vulnerable; other versions may also be
  affected.";


if (description)
{
 script_id(100098);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-04-02 19:55:50 +0200 (Thu, 02 Apr 2009)");
 script_bugtraq_id(34324);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Turnkey eBook Store 'keywords' Parameter Cross Site Scripting Vulnerability");
 desc = "

 Summary:
 " + tag_summary;

 script_description(desc);
 script_summary("Determine if Turnkey eBook Store is prone to Cross Site Scripting vulnerabilitie");
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

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

dir = make_list(cgi_dirs());

foreach d (dir)
{ 
 url = string(d, '/index.php?cmd=search&keywords="><script>alert(document.cookie);</script>');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( buf == NULL )continue;

 if ( egrep(pattern:"<script>alert\(document\.cookie\);</script>", string: buf) )
     
 	{    
       	  security_warning(port:port);
          exit(0);
        }
}

exit(0);
