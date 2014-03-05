# OpenVAS Vulnerability Test
# $Id: iis_xss_404.nasl 17 2013-10-27 14:01:43Z jan $
# Description: IIS XSS via 404 error
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
#
# Copyright:
# Copyright (C) 2002 Matt Moore
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
tag_summary = "This IIS Server appears to vulnerable to one of the cross site scripting
attacks described in MS02-018. The default '404' file returned by IIS uses scripting to output a link to 
top level domain part of the url requested. By crafting a particular URL it is possible to insert arbitrary script into the
page for execution.

The presence of this vulnerability also indicates that you are vulnerable to the other issues identified in MS02-018 (various remote buffer overflow and cross site scripting attacks...)";

# admins who installed this patch would necessarily not be vulnerable to CVE-2001-1325

if(description)
{
 script_id(10936);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4476, 4483, 4486);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_xref(name:"IAVA", value:"2002-A-0002");
 name = "IIS XSS via 404 error";
 script_name(name);
 script_cve_id("CVE-2002-0148", "CVE-2002-0150");     # lots of bugs rolled into one patch...
 
 desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS02-018.mspx");
 script_xref(name : "URL" , value : "http://jscript.dk/adv/TL001/");

 script_description(desc);
 
 summary = "Tests for IIS XSS via 404 errors";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# Check makes a request for non-existent HTML file. The server should return a 404 for this request.
# The unpatched server returns a page containing the buggy JavaScript, on a patched server this has been
# updated to further check the input...

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


banner = get_http_banner(port:port);
if ( "Microsoft-IIS" >!< banner ) exit(0);

if(get_port_state(port))
{ 
 req = http_get(item:"/blah.htm", port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if ( ! r ) exit(0);
 str1="urlresult";
 str2="+ displayresult +";

 if((str1 >< r) && (str2 >< r)) security_hole(port);
}
