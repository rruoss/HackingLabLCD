###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_SmallFTPD_40180.nasl 14 2013-10-27 12:33:37Z jan $
#
# SmallFTPD 'DELE' Command Remote Denial Of Service Vulnerability
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
tag_summary = "SmallFTPD is prone to a remote denial-of-service vulnerability.

Successful attacks will cause the application to crash, creating a denial-of-
service condition.

SmallFTPD 1.0.3 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100642);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-17 12:46:01 +0200 (Mon, 17 May 2010)");
 script_bugtraq_id(40180);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("SmallFTPD 'DELE' Command Remote Denial Of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40180");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/smallftpd/");

 script_description(desc);
 script_summary("Determine if SmallFTPD is prone to a remote denial-of-service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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

if(get_kb_item('ftp/'+port+'/broken'))exit(0);

if(!get_port_state(port)){
  exit(0);
}

banner = get_ftp_banner(port);

if(!banner || "smallftpd" >!< banner)exit(0);

version = eregmatch(pattern:"smallftpd ([0-9.]+)", string: banner);
vers = version[1];

if(!isnull(vers)) {

    if(version_is_less_equal(version:vers, test_version:"1.0.3") ) {
        security_hole(port: port);
        exit(0);

    }
}

exit(0);
