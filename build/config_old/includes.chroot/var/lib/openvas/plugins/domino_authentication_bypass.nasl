# OpenVAS Vulnerability Test
# $Id: domino_authentication_bypass.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Authentication bypassing in Lotus Domino
#
# Authors:
# Davy Van De Moere - CISSP (davy@securax.be) 
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
# Credits go to: Gabriel A. Maggiotti (for posting this bug on qb0x.net), and 
# to Javier Fernandez-Sanguino Peña (for the look-a-like nessus script, which
# checks for anonymously accessible databases.)
# Modified by Erik Anderson <eanders@pobox.com>
#
# Copyright:
# Copyright (C) 2002 Davy Van De Moere
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
tag_summary = "By creating a specially crafted url, the authentication mechanism of
Domino database can be circumvented. These urls should look like:

http://host.com/<databasename>.ntf<buff>.nsf/ in which <buff> has a
certain length.";

tag_solution = "Upgrade to the latest version of Domino.";

if(description)
{
 script_id(10953);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2001-1567");
 script_bugtraq_id(4022);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 name = "Authentication bypassing in Lotus Domino";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

script_description(desc);

summary = "Checks if Lotus Domino databases can be accessed by by-passing the required authentication";
 script_summary(summary);

script_category(ACT_GATHER_INFO);

script_copyright("This script is Copyright (C) 2002 Davy Van De Moere");

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
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

sig = get_http_banner(port:port);
if ( sig && "Lotus Domino" >!< sig ) exit(0);


report = string("These databases require a password, but this authentication\ncan be circumvented by supplying a long buffer in front of their name :\n");
vuln = 0;
dead = 0;

function test_cgi(port, db, db_bypass)
{
 local_var Forbidden, passed;

 if ( dead ) return 0;

 Forbidden = 0;

 r = http_keepalive_send_recv(port:port, data:http_get(item:db, port:port));
 if( r == NULL ) {
	dead = 1;
	return 0;
	}
 
 if(ereg(string:r, pattern:"^HTTP/[0-9]\.[0-9] 401 .*"))
 	{
	  Forbidden = 1;
	}

 passed = 0;
 r = http_keepalive_send_recv(port:port, data:http_get(item:db_bypass, port:port));
 
 if( r == NULL ) {
	dead = 1;
	return 0;
	}
 
 if(ereg(string:r, pattern:"^HTTP/[0-9]\.[0-9] 200 .*"))passed = 1;
 
 if((Forbidden == 1) && (passed == 1))
  {
    report = string(report, db, "\n"); 
    vuln = vuln + 1;
  }
 return(0);
}
 
 



test_cgi(port:port,
          db:"/log.nsf", 
          db_bypass:string("/log.ntf",crap(length:206,data:"+"),".nsf"));
 
test_cgi(port:port, 
          db:"/setup.nsf",
          db_bypass:string("/setup.ntf",crap(length:204,data:"+"),".nsf"));

test_cgi(port:port, 
          db:"/names.nsf",
          db_bypass:string("/names.ntf",crap(length:204,data:"+"),".nsf"));     
 
test_cgi(port:port, 
          db:"/statrep.nsf",
	  db_bypass:string("/statrep.ntf",crap(length:202,data:"+"),".nsf"));

test_cgi(port:port, 
          db:"/catalog.nsf",
          db_bypass:string("/catalog.ntf",crap(length:202,data:"+"),".nsf"));
          
test_cgi(port:port, 
          db:"/domlog.nsf",
          db_bypass:string("/domlog.ntf",crap(length:203,data:"+"),".nsf"));

test_cgi(port:port, 
          db:"/webadmin.nsf",
	  db_bypass:string("/webadmin.ntf",crap(length:201,data:"+"),".nsf"));

test_cgi(port:port, 
          db:"/cersvr.nsf",
	  db_bypass:string("/cersvr.ntf",crap(length:203,data:"+"),".nsf"));
          
test_cgi(port:port, 
          db:"/events4.nsf",
          db_bypass:string("/events4.ntf",crap(length:202,data:"+"),".nsf"));

test_cgi(port:port, 
         db:"/mab.nsf",
         db_bypass:string("/mab.ntf",crap(length:206,data:"+"),".nsf"));

test_cgi(port:port, 
         db:"/ntsync4.nsf",
         db_bypass:string("/ntsync4.ntf",crap(length:202,data:"+"),".nsf"));

test_cgi(port:port, 
         db:"/collect4.nsf",
         db_bypass:string("/collect4.ntf",crap(length:201,data:"+"),".nsf"));

test_cgi(port:port, 
        db:"/mailw46.nsf",
        db_bypass:string("/mailw46.ntf",crap(length:202,data:"+"),".nsf"));
          
test_cgi(port:port, 
        db:"/bookmark.nsf",
        db_bypass:string("/bookmark.ntf",crap(length:201,data:"+"),".nsf"));
          
test_cgi(port:port, 
          db:"/agentrunner.nsf",
          db_bypass:string("/agentrunner.ntf",crap(length:198,data:"+"),".nsf"));

test_cgi(port:port, 
          db:"/mail.box",
          db_bypass:string("/mailbox.ntf",crap(length:202,data:"+"),".nsf"));

test_cgi(port:port,
          db:"/admin4.nsf",
          db_bypass:string("/admin4.ntf",crap(length:203,data:"+"),".nsf"));

if(vuln)
  {
security_warning(port:port, data:string(report,"\n This is a severe risk,
as an attacker is able to access \n most of the authentication protected
databases. As such, \nconfidential information can be looked into and
\nconfigurations can mostly be altered. "));
}
