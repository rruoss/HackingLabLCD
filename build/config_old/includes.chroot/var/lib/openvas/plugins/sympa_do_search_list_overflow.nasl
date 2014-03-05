# OpenVAS Vulnerability Test
# $Id: sympa_do_search_list_overflow.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Sympa wwsympa do_search_list Overflow DoS
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
tag_summary = "The remote host is running SYMPA, an open source mailing list software.

This version of Sympa has a flaw in one of it's scripts (wwsympa.pl) which
would allow a remote attacker to overflow the sympa server.  Specifically,
within the cgi script wwsympa.pl is a do_search_list function which fails to perform
bounds checking.  An attacker, passing a specially formatted long string
to this function, would be able to crash the remote sympa server.  At the
time of this writing, the attack is only known to cause a Denial of Service
(DoS).";

tag_solution = "Update to version 4.1.2 or newer";

# Ref: Paul Johnson <baloo at ursine dot dyndns dot org>

if(description)
{
 script_id(14298);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_xref(name:"OSVDB", value:"8690");
 name = "Sympa wwsympa do_search_list Overflow DoS";

 script_name(name);
 
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

if(!get_port_state(port))
	exit(0);


function check(url)
{
	req = http_get(item:string(url, "home"), port:port);
	r = http_keepalive_send_recv(port:port, data:req);
	if ( r == NULL ) 
		exit(0);

	if ("www.sympa.org" >< r)
	{
		# jwl : thru 3.3.5.1 vuln
        	if(egrep(pattern:"www\.sympa\.org.*ALT=.Sympa ([0-2]\.|3\.[0-2]|3\.3\.[0-4]|3\.3\.5\.[01])", string:r))
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
