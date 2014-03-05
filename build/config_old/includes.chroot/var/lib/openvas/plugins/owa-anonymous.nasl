# OpenVAS Vulnerability Test
# $Id: owa-anonymous.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Outlook Web anonymous access
#
# Authors:
# Javier Fern�ndez-Sanguino Pe�a <jfs@computer.org>
# based on scripts made by Renaud Deraison <deraison@cvs.nessus.org>
# Slightly modified by rd to to do pattern matching.
#
# Copyright:
# Copyright (C) 2001 Javier Fern�ndez-Sanguino Pe�a
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
tag_summary = "It is possible to browse the information of the OWA server by accessing as an
anonymous user with the following URL:

http://www.example.com/exchange/root.asp?acs=anon

After this access, the anonymous user can search for valid users in the OWA 
server and can enumerate all users by accessing the following URL:

http://www.example.com/exchange/finduser/details.asp?obj=XXX
(where XXX is a string of 65 hexadecimal numbers)

Data that can be accessed by an anonymous user
may include: usernames, server names, email name accounts,
phone numbers, departments, office, management relationships...

This information will help an attacker to make social
engineering attacks with the knowledge gained. This attack
can be easily automated since, even if direct access to search
is not possible, you only need the cookie given on the anonymous
login access.

Administrators might be interested in consulting
the following URL:

http://support.microsoft.com/support/exchange/content/whitepapers/owaguide.doc";

tag_solution = "Disable anonymous access to OWA. Follow these steps:
	1. In Microsoft Exchange Administrator open the Configuration container.
	2. Choose Protocols, and then double-click HTTP (Web) Site Settings
	3. Unselect the 'Allow anonymous users to access 
	the anonymous public folders' check box.
	4. Select the Folder Shortcuts tab.
	5. Remove all folders which are allowed anonymous viewing.
        6. Choose OK.
	7. Remove the anonymous access from the login web pages.";

if(description)
{
 script_id(10781);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3301);
 script_cve_id("CVE-2001-0660");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "Outlook Web anonymous access";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;	
 script_description(desc);
 
 summary = "Outlook Web anonymous access";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2001 Javier Fern�ndez-Sanguino Pe�a");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if ( ! can_host_asp(port:port) ) exit(0);





 cgi = "/exchange/root.asp?acs=anon";
 if(is_cgi_installed_ka(item:cgi, port:port))
 {
  soc = http_open_socket(port);
  req = http_get(item:"/exchange/root.asp?acs=anon", port:port);
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if ("/exchange/logonfrm.asp" >< r)
  {
   soc = http_open_socket(port);
   req = http_get(item:"/exchange/logonfrm.asp", port:port);
   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   http_close_socket(soc);

   if (!("This page has been disabled" >< r))
   {
    security_warning(port);
   }
  }
 }
