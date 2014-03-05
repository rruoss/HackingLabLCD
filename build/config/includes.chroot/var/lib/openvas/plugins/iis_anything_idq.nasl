# OpenVAS Vulnerability Test
# $Id: iis_anything_idq.nasl 17 2013-10-27 14:01:43Z jan $
# Description: IIS IDA/IDQ Path Disclosure
#
# Authors:
# Filipe Custodio <filipecustodio@yahoo.com>
# Changes by rd :
# - description slightly modified to include a solution
#
# Copyright:
# Copyright (C) 2000 Filipe Custodio
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
tag_summary = "IIS 4.0 allows a remote attacker to obtain the real pathname
of the document root by requesting non-existent files with
.ida or .idq extensions.

An attacker may use this flaw to gain more information about
the remote host, and hence make more focused attacks.";

tag_solution = "Select 'Preferences ->Home directory ->Application',
and check the checkbox 'Check if file exists' for the ISAPI
mappings of your server.";

if(description)
{
 script_id(10492);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1065);
 script_cve_id("CVE-2000-0071");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 name = "IIS IDA/IDQ Path Disclosure";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Determines IIS IDA/IDQ Path Reveal vulnerability";
 
 script_summary(summary);
 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2000 Filipe Custodio");
 family = "Web Servers";
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

port = get_http_port(default:80);


sig = get_http_banner(port:port);
if ( "IIS" >!< sig ) exit(0);


if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 
 req = http_get(item:"/anything.idq", port:port);
 soc = http_open_socket(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 str = egrep( pattern:"^<HTML>", string:r ) - "<HTML>";
 str = tolower(str);
  
 if ( egrep(pattern:"[a-z]\:\\.*anything",string:str) ) {
   security_warning( port:port );
 } else {
   req = http_get(item:"/anything.ida", port:port);
   soc = http_open_socket(port);
   if(!soc)exit(0);
   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   http_close_socket(soc);
   str = egrep( pattern:"^<HTML>", string:r ) - "<HTML>";
   str = tolower(str);
   if ( egrep(pattern:"[a-z]\:\\.*anything", string:str) )
      security_warning( port:port );
   }
}
