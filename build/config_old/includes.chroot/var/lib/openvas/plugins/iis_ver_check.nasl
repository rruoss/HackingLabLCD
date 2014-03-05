# OpenVAS Vulnerability Test
# $Id: iis_ver_check.nasl 17 2013-10-27 14:01:43Z jan $
# Description: IIS Service Pack - 404
#
# Authors:
# SensePost
# Modification by David Maciejak
# <david dot maciejak at kyxar dot fr>
# based on 404print.c from Digital Defense
#
# Copyright:
# Copyright (C) 2003 SensePost & Copyright (C) 2004 David Maciejak
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
tag_summary = "The Patch level (Service Pack) of the remote IIS server appears to be lower 
than the current IIS service pack level. As each service pack typically
contains many security patches, the server may be at risk.

Caveat: This test makes assumptions of the remote patch level based on static 
return values (Content-Length) within the IIS Servers 404 error message.
As such, the test can not be totally reliable and should be manually confirmed.";

tag_solution = "Ensure that the server is running the latest stable Service Pack";

if(description)
{
 script_id(11874);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 name = "IIS Service Pack - 404";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "IIS Service Pack Check";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 SensePost & Copyright (C) 2004 David Maciejak");

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

# Check starts here
include("http_func.inc");
include("http_keepalive.inc");




port = get_http_port(default:80);

sig = get_http_banner(port:port);
if ( sig && "IIS" >!< sig ) exit(0);
if(! get_port_state(port)) exit(0);
r1 = http_get(item:"/openvas" + rand(), port:port);

r  = http_keepalive_send_recv(data:r1, port:port);
if ( r == NULL ) exit(0);
if (!ereg(pattern:"^HTTP.* 404 .*", string:r))exit(0);

v4 = egrep(pattern:"^Server:.*Microsoft-IIS/4\.0", string:r);
v5 = egrep(pattern:"^Server:.*Microsoft-IIS/5\.0", string:r);
v51 = egrep(pattern:"^Server:.*Microsoft-IIS/5\.1", string:r);
v6 = egrep(pattern:"^Server:.*Microsoft-IIS/6\.0", string:r);

cltmp = eregmatch(pattern:".*Content-Length: ([0-9]+).*", string:r);
if (isnull(cltmp)) exit(0);
cl=int(cltmp[1]);

ver = string("The remote IIS server *seems* to be ");

#if(v4)
#{
#        if (102 == cl)
#                ver = ver + string("Microsoft IIS 4 - Sp0\n");		
#	if (451 == cl)
#		ver = ver + string("Microsoft IIS 4 - SP6\n");
#	if (461 == cl)
#		ver = ver + string("Microsoft IIS 4 - SP3\n");
#}

if(v5)
{
#??
#        if(111 == cl)
#		ver = ver + string("Microsoft IIS 5 - SP4\n");
	if(3243 == cl)
		ver = ver + string("Microsoft IIS 5 - SP0 or SP1\n");
        if(2352 == cl)
                ver = ver + string("Microsoft IIS 5 - SP2 or SRP1\n");
        if(4040 == cl)
                ver = ver + string("Microsoft IIS 5 - SP3 or SP4\n");
}

if(v51)
{
        if (1330 == cl)
                ver = ver + string("Microsoft IIS 5.1 - SP2\n");		
	if (4040 == cl)
		ver = ver + string("Microsoft IIS 5.1 - SP0\n");
}

if(v6)
{
        if (2166 == cl)
                ver = ver + string("Microsoft IIS 6.0 - SP0\n");		
	if (1635 == cl)
		ver = ver + string("Microsoft IIS 6.0 - w2k3 build 3790\n");
}

if ( ver !=  "The remote IIS server *seems* to be " ) security_note(port:port, data:ver);
exit(0);
