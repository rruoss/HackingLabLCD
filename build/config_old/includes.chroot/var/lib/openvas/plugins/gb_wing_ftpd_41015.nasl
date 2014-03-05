###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wing_ftpd_41015.nasl 14 2013-10-27 12:33:37Z jan $
#
# Wing FTP Server 'PORT' Command Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "Wing FTP Server is prone to a denial-of-service vulnerability.

An attacker can exploit this issue to cause the server to crash,
resulting in a denial-of-service condition. Other attacks may also
be possible.

This issue is known to be exploitable in Windows environment; other
platforms may also be affected.

Wing FTP Server 3.1.2 is vulnerable; prior versions may also be
affected.";

tag_solution = "Updates are available. Please see the references for more details.";

if (description)
{
 script_id(100690);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-23 13:22:49 +0200 (Wed, 23 Jun 2010)");
 script_bugtraq_id(41015);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Wing FTP Server 'PORT' Command Denial Of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41015");
 script_xref(name : "URL" , value : "http://www.wftpserver.com/");
 script_xref(name : "URL" , value : "http://www.wftpserver.com/serverhistory.htm");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/511905");
 script_xref(name : "URL" , value : "http://blog.trendmicro.com/trend-micro-discovers-wing-ftp-server-port-command-dos-bug/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if Wing FTP Server version is < 3.2");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/ftp", 21);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(!get_port_state(port)){
  exit(0);
}

if(get_kb_item('ftp/'+port+'/broken'))exit(0);

if(!banner = get_ftp_banner(port)) exit(0);
if("220 Wing FTP Server" >!< banner)exit(0);

version = eregmatch(pattern:"Wing FTP Server ([^ ]+) ready", string:banner);

if( ! isnull(version[1]) ) {

    if( version_is_less(version:version[1], test_version:"3.2") ) {
        security_warning(port: port);
        exit(0);

    }
}

exit(0);