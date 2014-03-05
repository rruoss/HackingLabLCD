# OpenVAS Vulnerability Test
# $Id: DDI_FTP_Any_User_Login.nasl 17 2013-10-27 14:01:43Z jan $
# Description: FTP Service Allows Any Username
#
# Authors:
# H D Moore
#
# Copyright:
# Copyright (C) 2002 Digital Defense Inc.
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
tag_summary = "The FTP service can be accessed using any username and password.
Many other plugins may trigger falsely because of this, so 
OpenVAS enable some countermeasures.

** If you find a useless warning on this port, please inform
** the OpenVAS team so that we fix the plugins.";

tag_solution = "None";

if(description)
{
    script_id(10990);
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
    script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"0.0");
    script_tag(name:"risk_factor", value:"None");
    name = "FTP Service Allows Any Username";
    script_name(name);


    desc = "
    Summary:
    " + tag_summary + "
    Solution:
    " + tag_solution;
    script_description( desc);
    script_summary( "FTP Service Allows Any Username");
    script_category(ACT_GATHER_INFO);
    script_copyright("This script is Copyright (C) 2002 Digital Defense Inc.");

    script_family( "FTP");
    script_dependencies("ftpserver_detect_type_nd_version.nasl"); 
    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "solution" , value : tag_solution);
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
}


#
# The script code starts here
#
include('global_settings.inc');
include('ftp_func.inc');
include('misc_func.inc');

port = get_kb_item("Services/ftp");
if (!port)port = 21;
if (! get_port_state(port)) exit(0);

n_cnx = 0; n_log = 0;

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);


for (i = 0; i < 4; i ++)
{
 soc = open_sock_tcp(port);
 if(soc)
 {
   n_cnx ++;
   u = rand_str(); p = rand_str();
   if (ftp_authenticate(socket:soc, user: u, pass: p))
     n_log ++;
   else
     exit(0);
   ftp_close(socket: soc);
 }
 else
  sleep(1);
}

debug_print('n_log=', n_log, '/ n_cnx=', n_cnx, '\n');

if (n_cnx > 1 && n_log >= n_cnx - 1)	# >= n_cnx ?
{
 set_kb_item(name:"ftp/" + port + "/AnyUser", value:TRUE);
 if (report_verbosity > 1) security_note(port:port);
} 
