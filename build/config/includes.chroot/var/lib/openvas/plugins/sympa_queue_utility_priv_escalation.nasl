# OpenVAS Vulnerability Test
# $Id: sympa_queue_utility_priv_escalation.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Sympa queue utility privilege escalation vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
tag_summary = "The remote host seems to be running sympa, an open source mailing list 
management software.

The remote version of this software contains a vulnerability which can be 
exploited by malicious local user to gain escalated privileges.

This issue is due to a boundary error in the queue utility when 
processing command line arguments. This can cause a stack based buffer 
overflow.";

tag_solution = "Update to Sympa version 4.1.3 or newer
";
# Ref: Erik Sjölund

if(description)
{
 script_id(16387);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(12527);
 script_cve_id("CVE-2005-0073");
 name = "Sympa queue utility privilege escalation vulnerability";

 script_name(name);
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 summary = "Checks for sympa version";
 script_summary(summary);
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
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
# the code
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

	if ("http://www.sympa.org/" >< r)
	{
        	if(egrep(pattern:".*ALT=.Sympa (2\.|3\.|4\.0|4\.1\.[012][^0-9])", string:r))
 		{
 			security_warning(port);
			exit(0);
		}
	}
}


foreach dir (cgi_dirs())
{
 check(url:dir);
}
