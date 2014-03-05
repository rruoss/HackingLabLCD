###############################################################################
# OpenVAS Vulnerability Test
# $Id: cherokee_36874.nasl 15 2013-10-27 12:49:54Z jan $
#
# Cherokee Directory Traversal Vulnerability
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
tag_summary = "Cherokee is prone to a directory-traversal vulnerability because it
fails to sufficiently sanitize user-supplied input data.

Exploiting the issue may allow an attacker to obtain sensitive
information that could aid in further attacks.

Cherokee 0.5.4 and prior versions are vulnerable.";


if (description)
{
 script_id(100326);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-30 14:42:19 +0100 (Fri, 30 Oct 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2009-3902");
 script_bugtraq_id(36874);
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Cherokee Directory Traversal Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36874");
 script_xref(name : "URL" , value : "http://www.alobbs.com/modules.php?op=modload&amp;name=cherokee&amp;file=index");
 script_xref(name : "URL" , value : "http://freetexthost.com/ncyss3plli");

 script_description(desc);
 script_summary("Determine if Cherokee Web Server is prone to a directory-traversal vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if("Cherokee" >< banner && "Win" >< banner) {
       
   url = string("/\\../\\../\\../boot.ini");
   req = http_get(item:url, port:port);
   buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
   if( buf == NULL )exit(0);

   if(egrep(pattern:"\[boot loader\]", string: buf)) {
      security_warning(port:port);
      exit(0); 
   }   
}

exit(0);
