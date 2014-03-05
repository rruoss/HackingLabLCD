# OpenVAS Vulnerability Test
# $Id: remote-detect-sybase-easerver.nasl 16 2013-10-27 13:09:52Z jan $
# Description: This script ensure that the Sybase EAServer is installed and running
#
# remote-detect-sybase-easerver.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
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
tag_summary = "The remote host is running the Sybase Enterprise Application Server. 
Sybase EAServer is the open application server from Sybase Inc 
an enterprise software and services company exclusively focused on managing and mobilizing information.";

tag_solution = "It's recommended to allow connection to this host only from trusted hosts or networks,
or disable the service if not used.";



if(description)
{
script_id(80006);
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 16 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2008-09-09 16:54:39 +0200 (Tue, 09 Sep 2008)");
script_tag(name:"cvss_base", value:"0.0");
script_tag(name:"risk_factor", value:"None");
name = "Sybase Enterprise Application Server service detection";
script_name(name);
 
desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;
script_description(desc); 

summary = "Ensure that the remote host is running a Sybase EAServer ";

script_summary(summary);

script_category(ACT_GATHER_INFO);

script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
family = "Service detection";
script_family(family);
script_dependencies("find_service.nasl");
script_require_ports("Services/www");


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
include("openvas-https.inc");


http_servers = get_kb_list("Services/www");
soc_timeout = 10;

# if the server accept clear http
if(http_server)
{

foreach port (http_servers)
{
# connect to the remote host and send the request on each port
soc = open_sock_tcp(port);
req = http_get(item:"/", port:port, timeout:soc_timeout);
send(socket:soc, data:req);

# read the reply
reply = recv(socket:soc, length:4096);

if(reply)
{
if(("<TITLE>Sybase EAServer<" >< reply || egrep(pattern:"Sybase EAServer", string:reply))) 
set_kb_item (name:"SybaseEAServer/installed", value:TRUE);
security_note(port);
}
}
}

else 
{
# Force this if the server only accept ssl connections
https_servers = get_kb_list("Services/https");

foreach port (https_servers)
r= https_req_get(port:port, request:"/" );

if( r == NULL )exit(0);
if(("<TITLE>Sybase EAServer<" >< r || egrep(pattern:"Sybase EAServer", string:r)))
set_kb_item (name:"SybaseEAServer/installed", value:TRUE);
security_note(port);
}
