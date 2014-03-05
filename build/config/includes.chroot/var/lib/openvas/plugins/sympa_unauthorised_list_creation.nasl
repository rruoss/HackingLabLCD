# OpenVAS Vulnerability Test
# $Id: sympa_unauthorised_list_creation.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Sympa unauthorised list creation security issue
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
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
tag_summary = "The remote host seems to be running sympa, an open source mailing list software.

This version of Sympa has an authentication flaw within the web interface.

An attacker, exploiting this flaw, would be able to bypass security
mechanisms resulting in the ability to perform listmaster functions 
remotely.";

tag_solution = "Update to version 4.1.2 or newer";

#  Ref: Sympa Team - August 2004


if(description)
{
script_id(14300);
script_version("$Revision: 17 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
script_bugtraq_id(10941);
script_tag(name:"cvss_base", value:"4.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");

 name = "Sympa unauthorised list creation security issue";

 script_name(name);
 script_tag(name:"risk_factor", value:"Medium");
 desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution + "

";
 script_description(desc);
 
 summary = "Checks for sympa version";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
}
script_xref(name : "URL" , value : "http://www.sympa.org/");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

function check(url)
{
req = http_get(item:string(url, "home"), port:port);
r = http_keepalive_send_recv(port:port, data:req);
if ( r == NULL ) exit(0);

    #We need to match this
    
    #TD NOWRAP><I>Powered by</I></TD>
    #<TD><A HREF="http://www.sympa.org/">
    #       <IMG SRC="/icons/sympa/logo-s.png" ALT="Sympa 4.1.2" BORDER="0" >
	if ("http://www.sympa.org/" >< r)
	{
        	if(egrep(pattern:".*ALT=.Sympa (2\.|3\.|4\.0|4\.1\.[01])", string:r))
 		{
 			security_warning(port);
			exit(0);
		}
	}
 
}

check(url:"");
check(url:"/wws/");
check(url:"/wwsympa/");

foreach dir (cgi_dirs())
{
 check(url:dir);
}
