# OpenVAS Vulnerability Test
# $Id: domino_default_db.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Lotus Domino administration databases
#
# Authors:
# Javier Fernandez-Sanguino Peña <jfs@computer.org>
# based on the iis_samples.nasl script written by Renaud Deraison
# Script was modified by Jasmin Amidzic <jasminsabina@yahoo.com>.
#
# Copyright:
# Copyright (C) 2001 Javier Fernández-Sanguino Peña
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
tag_summary = "This script determines if some default databases can be read
remotely.

An anonymous user can retrieve information from this
Lotus Domino server: users, databases, configuration
of servers (including operating system and hard
disk partitioning), logs of access to users (which
could expose sensitive data if GET html forms are used)..

This issues are discussed in  'Lotus White Paper:
A Guide to Developing Secure Domino Applications' (december 1999)
http://www.lotus.com/developers/devbase.nsf/articles/doc1999112200";

tag_solution = "verify all the ACLs for these databases and remove those not needed
# This really could be high if, for example some 
# sensitive data, but same databases do not give
# much information. Make separate tests for each?";

if(description)
{
 script_id(10629);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5101, 881);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2000-0021", "CVE-2002-0664");

 name = "Lotus Domino administration databases";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Checks if Lotus Domino administration databases can be anonymously accessed";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2001 Javier Fernández-Sanguino Peña");
# Maybe instead of Web application abuses this family should be called HTTP server abuses
 family = "Web Servers";
 script_family(family);
# This should also depend on finding a Lotus Domino server
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
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.10629";
SCRIPT_DESC = "Lotus Domino administration databases";

auth = NULL;

function test_cgi(port, db, output)
{
 ok = is_cgi_installed_ka(port:port, item:db);
 if(ok)
  {
  	# Check that the remote db is not actually password protected
  	req = http_get(item:db, port:port);
	r = http_keepalive_send_recv(port:port, data:req);
	
	if("Please identify yourself" >!< r &&
	   'type="password"' >!< r && 
	   "<TITLE>Server Login</TITLE>" >!< r)
		{
		report = string(report, ". ", db, " this must be considered a security risk since ", output,"\n");
		set_kb_item(name:string("www/domino/", port, "/db"), value:db);
   
                ## build cpe and store it as host_detail
                cpe = build_cpe(value:db, exp:"^([0-9.]+)", base:"cpe:/a:lotus:domino_server:");
                if(!isnull(cpe))
                   register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

		}
	else auth += ". " + db + '\n';
  }
 return(0);
}
 
 
report = "";

port = get_http_port(default:80);

sig = get_http_banner(port:port);
if ( sig && "Lotus Domino" >!< sig ) exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 
 req = http_head(item:"/", port:port);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 close(soc);
 

 
 
  test_cgi(port:port, 
 	  db:"/log.nsf",
	  output:"the server log can be retrieved");
 
  test_cgi(port:port, 
 	  db:"/setup.nsf",
	  output:"the server might be configured remotely or the current setup might be downloaded");
	  
  test_cgi(port:port, 
 	  db:"/catalog.nsf",
	  output:"the list of databases in the server can be retrieved");
 
  test_cgi(port:port, 
 	  db:"/statrep.nsf",
	  output:"the reports generated by administrators can be read anoymously");

  test_cgi(port:port, 
 	  db:"/names.nsf",
	  output:"the users and groups in the server can be accessed anonymously, in some cases, access to the hashed passwords will be possible");
	  
  test_cgi(port:port, 
 	  db:"/domlog.nsf",
	  output:"the logs of the domain servers  can be read anonymously");

  test_cgi(port:port, 
 	  db:"/webadmin.nsf",
	  output:"the server administration database can be read anonymously");

  test_cgi(port:port, 
 	  db:"/cersvr.nsf",
	  output:"the information on the server certificates can be read anonymously");
	  
  test_cgi(port:port, 
 	  db:"/events4.nsf",
	  output:"the list of events that have taken place can be read anonymously, this might lead to information disclosure of users and hidden databases");

  test_cgi(port:port,
  	   db:"/zmevladm.nsf",
	   output:"it provides arbitrary users with Manager level access, which allows the users to read or modify the import/export scripts");

 # We should add more info here on the output: on how this database
 # affects the server
 
 
  foreach db (make_list("/mab.nfs", "/ntsync4.nsf", "/collect4.nsf", 
  		 	"/mailw46.nsf", "/bookmark.nsf", "/agentrunner.nsf",
			"/mail.box", "/admin4.nsf", "/catalog.nsf", 
			"/AgentRunner.nsf", "/certlog.nsf", "/cpa.nsf",
			"/domcfg.nsf", "/domguide.nsf", "/domlog.nsf",
			"/doc/dspug.nsf", "/doc/helpadmn.nsf",
			"/doc/javapg.nsf", "/doc/readmec.nsf",
			"/doc/readmes.nsf", "/doc/svrinst.nsf", 
			"/doc/wksinst.nsf", "/archive/a_domlog.nsf",
			"/archive/l_domlog.nsf", "/help/decsdoc.nsf",
			"/help/dols_help.nsf", "/help/help5_admin.nsf",
			"/help/help5_client.nsf", "/help/help5_designer.nsf",
			"/help/lccon.nsf", "/help/lsxlc.nsf", 
			"/help4.nsf", "/homepage.nsf", "/sample/faqw46.nsf",
			"/sample/framew46.nsf", "/smtpibwq.nsf", 
			"/smtpobwq.nsf", "/smtptbls.nsf", "/statmail.nsf",
			"/statrep.nsf", "/stats675.nsf", "/lccon.nsf", 
			"/loga4.nsf", "/helplt4.nsf", "/qstart.nsf", 
			"/quickstart/qstart50.nsf", "/quickstart/wwsample.nsf",
			"/mtabtbls.nsf", "/names.nsf", "/proghelp/KBCCV11.NSF",
			"/doladmin.nsf", "/busytime.nsf", "/reports.nsf",
			"/iNotes/Forms5.nsf", "/mail/admin.nsf",
			"/software.nsf", "/domino.nsf", "/books.nsf",
			"/default.nsf", "/db.nsf", "/database.nsf",
			"/users.nsf", "/groups.nsf", "/group.nsf", "/user.nsf",
			"/ldap.nsf", "/notes.nsf", "/secret.nsf",
			"/accounts.nsf", "/products.nsf", "/account.nsf", 
			"/secure.nsf", "/hidden.nsf", "/public.nsf", 
			"/private.nsf", "/welcome.nsf", "/calendar.nsf",
			"/nntppost.nsf", "/help/readme.nsf", "/help/help6_client.nsf",
			"/help/help6_designer.nsf", "/help/help6_admin.nsf",
			"/certsrv.nsf", "/dbdirman.nsf", "/lndfr.nsf",
			"/home.nsf" ))
 
  	test_cgi(port:port, 
 	  db:db,
	  output:"this database can be read anonymously");


 if(report)
  {
  report = string("We found the following domino databases :\n", report);
  security_hole(port:port, data:report);
  }

  if(auth)
  {
   security_hole(data:'The following databases exists but are password-protected:\n'+auth, port:port);
  }
    exit(0);

}




