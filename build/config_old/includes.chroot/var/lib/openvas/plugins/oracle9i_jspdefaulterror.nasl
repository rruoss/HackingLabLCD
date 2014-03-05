# OpenVAS Vulnerability Test
# $Id: oracle9i_jspdefaulterror.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Oracle 9iAS default error information disclosure
#
# Authors:
# Javier Fernandez-Sanguino <jfs@computer.org>
#
# Copyright:
# Copyright (C) 2003 Javier Fernandez-Sanguino
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
tag_solution = "Ensure that virtual paths of URL is different from the actual directory 
path. Also, do not use the <servletzonepath> directory in 
'ApJServMount <servletzonepath> <servletzone>' to store data or files.

Upgrading to Oracle 9iAS 1.1.2.0.0 will also fix this issue.



http://www.nextgenss.com/papers/hpoas.pdf";

tag_summary = "It is possible to obtain the physical path of the remote server
web root.

Description :

Oracle 9iAS allows remote attackers to obtain the physical path of a file
under the server root via a request for a non-existent .JSP file. The default
error generated leaks the pathname in an error message.";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(11226);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3341);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2001-1372");
 name = "Oracle 9iAS default error information disclosure";
 script_name(name);
 

 script_description(desc);
 
 summary = "Tries to retrieve the phisical path of files through Oracle9iAS";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Javier Fernandez-Sanguino");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 script_xref(name : "URL" , value : "http://otn.oracle.com/deploy/security/pdf/jspexecute_alert.pdf");
 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/278971");
 script_xref(name : "URL" , value : "http://www.cert.org/advisories/CA-2002-08.html");
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{ 
# Make a request for the configuration file

     errorjsp = "/nonexistant.jsp";
     req = http_get(item: errorjsp, port: port);
     soc = http_open_socket(port);
     if(soc) {
        send(socket:soc, data:req);
         r = http_recv(socket:soc);
         http_close_socket(soc);
	 location = egrep(pattern:"java.io.FileNotFoundException", string :r);
	 if ( location )  {
 	 # Thanks to Paul Johnston for the tip that made the following line
	 # work (jfs)
         # MA 2005-02-13: This did not work on Windows where / is replaced by \
	     path = ereg_replace(pattern: strcat("(java.io.FileNotFoundException: )(.*[^/\])[/\]+",substr(errorjsp, 1),".*"), replace:"\2", string: location);
	     security_warning(port:port, data:desc + '\n\nPlugin output :\n\n' + string("The web root physical is ", path ));
	 }
     } # if (soc)
}
