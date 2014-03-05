# OpenVAS Vulnerability Test
# $Id: apache_slash.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Check for Apache Multiple / vulnerability
#
# Authors:
# John Lampe (j_lampe@bellsouth.net)
# changes by rd : - script description
#                 - more verbose report
#                 - check for k < 16 in find_index()
#                 - script id
#
# Copyright:
# Copyright (C) 2000 John Lampe <j_lampe@bellsouth.net>
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
tag_summary = "Certain versions of Apache for Win32 have a bug wherein remote users
can list directory entries.  Specifically, by appending multiple /'s
to the HTTP GET command, the remote Apache server will list all files
and subdirectories within the web root (as defined in httpd.conf).";

tag_solution = "Upgrade to the most recent version of Apache at www.apache.org";

if(description)
{
  script_id(10440);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1284);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2000-0505");
  script_name("Check for Apache Multiple / vulnerability");
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);
  script_summary("Send multiple /'s to Windows Apache Server");
  script_category(ACT_GATHER_INFO);
  script_family("Remote file access");
  script_copyright("Copyright (C) 2000 John Lampe <j_lampe@bellsouth.net>");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}



#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");



function find_index(k) {

    if(k < 16)k = 17;
    for (q=k-16; q<k; q=q+1) {
            buf = http_get(item:crap(length:q, data:"/"), port:port);
	    incoming = http_keepalive_send_recv(port:port, data:buf);
	    if ( incoming == NULL ) exit(0);
            if ("Index of /" >< incoming)  {
                my_warning = "
It is possible to list a directories contents by appending multiple /'s
in the HTTP GET command, this is only
a vulnerability on Apache/Win32 based webservers. ";
                my_warning = my_warning + string (q, " slashes will cause the directory contents to be listed", "\n\n")
;
                my_warning = my_warning +
"Solution: Upgrade to the most recent version of Apache at www.apache.org";

                security_warning(port:port, data:my_warning);
                http_close_socket(soc);
                exit(0);
            }
         
    }
    exit(0);
}




port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);

if ( "Apache" >!< banner  ) exit(0);
if ( !thorough_tests && "Win32" >!< banner )  exit(0);



req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);
if ( "Index of /" >< res ) exit(0);

if(get_port_state(port)) {
    for (i=2; i < 512; i=i+16) {
            buf = http_get(item:crap(length:i, data:"/"), port:port);
	    incoming = http_keepalive_send_recv(port:port, data:buf);
	    if(incoming == NULL)exit(0);
            if ("Forbidden" >< incoming) {
                  find_index(k:i);
            }
        
    }
}
