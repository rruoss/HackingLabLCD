# OpenVAS Vulnerability Test
# $Id: bookreview_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: BookReview Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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
tag_summary = "The remote web server contains a CGI which is vulnerable to multiple cross site 
scripting vulnerabilities.

Description :

The remote host is running the BookReview software.

The remote version of this software is vulnerable to multiple cross-site 
scripting vulnerabilities due to a lack of sanitization of user-supplied
data.

Successful exploitation of this issue may allow an attacker to use the
remote server to perform an attack against a third-party user.";

tag_solution = "None at this time";

if(description)
{
 script_id(18375);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_cve_id("CVE-2005-1782");
 script_bugtraq_id(13783);
 script_xref(name:"OSVDB", value:"16871");
 script_xref(name:"OSVDB", value:"16872");
 script_xref(name:"OSVDB", value:"16873");
 script_xref(name:"OSVDB", value:"16874");
 script_xref(name:"OSVDB", value:"16875");
 script_xref(name:"OSVDB", value:"16876");
 script_xref(name:"OSVDB", value:"16877");
 script_xref(name:"OSVDB", value:"16878");
 script_xref(name:"OSVDB", value:"16879");
 script_xref(name:"OSVDB", value:"16880");
 script_xref(name:"OSVDB", value:"16881");

 name = "BookReview Multiple Cross-Site Scripting Vulnerabilities";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);

 summary = "Checks for unathentication access to admin.asp";

 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_family("Web application abuses");
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");

 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);

function check(url)
{
 req = http_get(item:url +"/add_url.htm?node=%3Cscript%3Ealert('XSS')%3C/script%3E", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( "<script>alert('XSS')</script>XSS" >< res && 'Powered by BookReview' >< res )
 {
        security_warning(port);
        exit(0);
 }
}

foreach dir ( cgi_dirs() )
  check(url:dir);
