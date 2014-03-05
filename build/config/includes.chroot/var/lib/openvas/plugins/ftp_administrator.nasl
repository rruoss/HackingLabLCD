# OpenVAS Vulnerability Test
# $Id: ftp_administrator.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Windows Administrator NULL FTP password
#
# Authors:
# Keith Young <Keith.Young@co.mo.md.us>
#
# Copyright:
# Copyright (C) 2002 Keith Young
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
tag_solution = "Change the Administrator password on this host.";

tag_summary = "The remote server is incorrectly configured 
with a NULL password for the user 'Administrator' and has 
FTP enabled.";
 
if(description)
{
 script_id(11160);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Windows Administrator NULL FTP password");
	     

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
script_summary("Checks for a NULL Windows Administrator FTP password");

 script_category(ACT_GATHER_INFO);

 script_family("FTP");
 
 script_copyright("This script is Copyright (C) 2002 Keith Young");
 
 script_dependencies("find_service.nasl", "DDI_FTP_Any_User_Login.nasl");
 script_require_ports("Services/ftp", 21);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here : 
#

include('ftp_func.inc');

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(get_port_state(port))
{
 if(get_kb_item("ftp/" + port + "/AnyUser"))exit(0);
 
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(ftp_authenticate(socket:soc, user:"Administrator", pass:""))security_hole(port);
 }
}
