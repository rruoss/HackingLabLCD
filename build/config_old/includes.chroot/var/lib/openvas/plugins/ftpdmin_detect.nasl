###############################################################################
# OpenVAS Vulnerability Test
# $Id: ftpdmin_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Ftpdmin Detection
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
tag_summary = "Ftpdmin is running at this port. Ftpdmin is a minimal Windows FTP server.";

desc = "

 Summary:
 " + tag_summary;


if (description)
{
 script_id(100131);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-04-13 18:06:40 +0200 (Mon, 13 Apr 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Ftpdmin Detection");  

 script_description(desc);
 script_summary("Check for Ftpdmin");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/ftp", 21);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.sentex.net/~mwandel/ftpdmin/");
 exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

if(!banner = get_ftp_banner(port:port))exit(0);

if(!isnull(banner)) {
 if("Minftpd" >< banner) {

   vers = string("unknown");

   soc = open_sock_tcp(port);
   if (! soc) exit(0);
   ftp_recv_line(socket:soc);

   syst = string("syst\r\n");
   send(socket:soc, data:syst);
   line = ftp_recv_line(socket:soc);
   ftp_close(socket: soc);

   version = eregmatch(pattern: "^215.*ftpdmin v\. ([0-9.]+)", string: line);

   if(!isnull(version[1])) {
    vers = version[1];
   }  

    set_kb_item(name:"ftpdmin/Ver", value:vers);

    info = string("\n\nFtpdmin Version '");
    info += string(vers);
    info += string("' was detected on the remote host.\n");

    desc = desc + info;

       if(report_verbosity > 0) {
         security_note(port:port,data:desc);
       }
       exit(0);
 

 }
}  

exit(0);
