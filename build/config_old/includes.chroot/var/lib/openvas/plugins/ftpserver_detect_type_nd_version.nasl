# OpenVAS Vulnerability Test
# $Id: ftpserver_detect_type_nd_version.nasl 41 2013-11-04 19:00:12Z jan $
# Description: FTP Server type and version
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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
tag_summary = "This detects the FTP Server type and version by connecting to the server and
processing the buffer received.
The login banner gives potential attackers additional information about the
system they are attacking. Versions and Types should be omitted
where possible.";

tag_solution = "Change the login banner to something generic.";

if(description)
{
 script_id(10092);
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"1.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Low");
 name = "FTP Server type and version";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "FTP Server type and version";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 1999 SecuriTeam");
 family = "General";
 script_family(family);
 script_require_ports("Services/ftp", 21);
 script_dependencies("find_service_3digits.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (!port) port = 21;

if(!get_port_state(port))exit(0);

banner = get_ftp_banner(port: port);

if(banner)
{
 if("NcFTPd" >< banner)set_kb_item(name:"ftp/ncftpd", value:TRUE);
 if(egrep(pattern:".*icrosoft FTP.*",string:banner))set_kb_item(name:"ftp/msftpd", value:TRUE);
 if(egrep(pattern:".*heck Point Firewall-1 Secure FTP.*", string:banner))set_kb_item(name:"ftp/fw1ftpd", value:TRUE);
 if(egrep(pattern:".*Version wu-.*", string:banner))set_kb_item(name:"ftp/wuftpd", value:TRUE);
 if(egrep(pattern:".*xWorks.*", string:banner))set_kb_item(name:"ftp/vxftpd", value:TRUE);
 data = string("Remote FTP server banner :\n", banner);
 security_note(port:port, data:data);
}
