###############################################################################
# OpenVAS Vulnerability Test
# $Id: burning_board_3_0_5_input_validation.nasl 15 2013-10-27 12:49:54Z jan $
#
# Woltlab Burning Board Multiple Input Validation Vulnerabilites
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
tag_summary = "Woltlab Burning Board is prone to multiple input-validation vulnerabilities, including:

  - Multiple security that may allow attackers to delete private messages
  - A cross-site scripting vulnerability
  - Multiple URI redirection vulnerabilities

  Attackers can exploit these issues to delete private messages,
  execute arbitrary script code, steal cookie-based authentication
  credentials and redirect users to malicious sites.

 Vulnerable:  	 
  Woltlab Burning Board 3.0.5
  Woltlab Burning Board 3.0.3 PL 1
  Woltlab Burning Board 3.0";


if (description)
{
 script_id(100056);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-13 06:42:27 +0100 (Fri, 13 Mar 2009)");
 script_bugtraq_id(34057);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Woltlab Burning Board Multiple Input Validation Vulnerabilites");
 desc = "

 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if Woltlab Burning Board is prone to Multiple Input Validation Vulnerabilites");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34057");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

dir = make_list("/forum","/board",cgi_dirs());

foreach d (dir)
{ 
 url = string(d, "/wcf/acp/dereferrer.php?url=javascript:alert(document.cookie);");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;
 
 if (egrep(pattern:".*<a href=.javascript:alert\(document.cookie\);.>javascript:alert\(document.cookie\);</a>.*", string: buf)
    )
     
 	{    
       	  security_warning(port:port);
          exit(0);
        }
}

exit(0);
