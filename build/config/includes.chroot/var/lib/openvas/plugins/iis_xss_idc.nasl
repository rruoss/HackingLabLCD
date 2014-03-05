# OpenVAS Vulnerability Test
# $Id: iis_xss_idc.nasl 17 2013-10-27 14:01:43Z jan $
# Description: IIS XSS via IDC error
#
# Authors:
# Geoffroy Raimbault <graimbault@lynx-technologies.com>
# www.lynx-technologies.com
#
# Copyright:
# Copyright (C) 2002 Geoffroy Raimbault/Lynx Technologies
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
tag_summary = "This IIS Server appears to be vulnerable to a Cross
Site Scripting due to an error in the handling of overlong requests on
an idc file. It is possible to inject Javascript
in the URL, that will appear in the resulting page.";

if(description)
{
 script_id(11142);
 script_version("$Revision: 17 $");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5900);
 name = "IIS XSS via IDC error";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary;


 script_description(desc);

 summary = "Tests for IIS XSS via IDC errors";


script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2002 Geoffroy Raimbault/Lynx Technologies");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_xref(name : "URL" , value : "http://online.securityfocus.com/bid/5900");
 script_xref(name : "URL" , value : "http://www.ntbugtraq.com/default.asp?pid=36&amp;sid=1&amp;A2=ind0210&amp;L=ntbugtraq&amp;F=P&amp;S=&amp;P=1391");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);
sig = get_http_banner(port:port);
if ( sig && "Server: Microsoft/IIS" >!< sig ) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

# We construct the malicious URL with an overlong idc filename
filename = string("/<script></script>",crap(334),".idc");
req = http_get(item:filename, port:port);

r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
str="<script></script>";
if((str >< r)) security_warning(port);
