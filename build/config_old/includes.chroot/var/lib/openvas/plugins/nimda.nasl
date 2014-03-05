# OpenVAS Vulnerability Test
# $Id: nimda.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Tests for Nimda Worm infected HTML files
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
# June 4, 2002 Revision 1.9 Additional information and refrence information
# added by Michael Scheidell SECNAP Network Security, LLC June 4, 2002
#
# Copyright:
# Copyright (C) 2001 Matt Moore
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
tag_summary = "Your server appears to have been compromised by the 
Nimda mass mailing worm. It uses various known IIS 
vulnerabilities to compromise the server.

Anyone visiting compromised Web servers will be prompted to
download an .eml (Outlook Express) email file, which
contains the worm as an attachment. 

Also, the worm will create open network shares on the infected 
computer, allowing access to the system. During this process
the worm creates the guest account with Administrator privileges.";

tag_solution = "Take this server offline immediately, rebuild it and
apply ALL vendor patches and security updates before reconnecting
server to the internet, as well as security settings discussed in 
Additional Information section of Microsoft's web site at

http://www.microsoft.com/technet/security/bulletin/ms01-044.mspx

Check ALL of your local Microsoft based workstations for infection.
Note: this worm has already infected more than 500,000 computers
worldwide since its release in late 2001.

See:  http://www.cert.org/advisories/CA-2001-26.html";


if(description)
{
 script_id(10767);
 script_version("$Revision: 17 $");
 script_cve_id("CVE-2001-0545", "CVE-2001-0508", "CVE-2001-0544", "CVE-2001-0506",
               "CVE-2001-0507");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 name = "Tests for Nimda Worm infected HTML files";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 summary = "Tests for Nimda Worm infected HTML files";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2001 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# Check for references to readme.eml in default HTML page..

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 r = http_get_cache(item:"/", port:port);
 if(r && "readme.eml" >< r)	
 	security_hole(port);
}
