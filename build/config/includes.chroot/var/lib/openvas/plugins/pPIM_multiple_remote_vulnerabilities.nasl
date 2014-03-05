###############################################################################
# OpenVAS Vulnerability Test
# $Id: pPIM_multiple_remote_vulnerabilities.nasl 15 2013-10-27 12:49:54Z jan $
#
# pPIM Multiple Remote Vulnerabilities
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
tag_summary = "This host is running pPIM. pPIM is an information manger that can hold contacts, events in a
  calendar, links, send emails, check email, store notes, and uploads files.

  pPIM is prone to multiple vulnerabilities, including two security-bypass
  issues, a cross-site scripting issue, and a file-upload issue.

  Attackers can exploit these issues to:

  - execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site
  - steal cookie-based authentication credentials
  - delete local files within the context of the webserver process
  - upload arbitrary PHP scripts and execute them in the context of the webserver
  - change user passwords

  These issues affect pPIM 1.0 and prior versions.

  Seee http://www.phlatline.org/index.php?page=prod-ppim and http://www.securityfocus.com/bid/30627
  for further informations.";

tag_solution = "Uninstall pPIM.";

if (description)
{
 script_id(100005);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-02 16:07:07 +0100 (Mon, 02 Mar 2009)");
 script_tag(name:"cvss_base", value:"8.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
 script_cve_id("CVE-2008-4425");
 script_bugtraq_id(30627);
 script_tag(name:"risk_factor", value:"Critical");

 script_name("pPIM Multiple Remote Vulnerabilities");
 desc = "

 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 script_summary("pPIM Multiple Remote Vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);

dir = make_list("/ppim", cgi_dirs());

foreach d (dir)
{

 url = string(d, "/Readme.txt");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL )exit(0);
 
 if( "pPIM" >< buf ) {
  ver = eregmatch(string: buf, pattern: "Version ([0-9\.0-9]+)");
  if ( !isnull(ver[1]) ) {
   version = int( str_replace(find: '.', string: ver[1], replace: "") );
   if( version > 0 && version <= 10 ) {
        security_hole(port:port);
	exit(0);
   }
  } 
 } 
 else {
       # perhaps user has removed Readme.txt
   	url = string(d, "/upload.php");
	req = http_get(item:url, port:port);
	buf = http_keepalive_send_recv(port:port, data:req, bodyonly:0);
	if( buf == NULL )exit(0);

        if( egrep(pattern: "Location:.login\.php\?login=1", string: buf) ) {

	 url = string(d, "/upload.php?login=1");
	 req = http_get(item:url, port:port);
	 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:0);
	 if( buf == NULL )exit(0);

	 if ( egrep(pattern: 'NAME="userfile"', string: buf ) &&
	      egrep(pattern: 'name="submitupload"', string: buf) )
	  {
	  	        security_hole(port:port);
			exit(0);
	  }  
        } 
	#user installed ppim without password protection#
	else if ( egrep(pattern: 'NAME="userfile"', string: buf ) &&
                  egrep(pattern: 'name="submitupload"', string: buf) )
 	{
		security_hole(port:port);
		exit(0);
	}  
      }  
}

exit(0);
