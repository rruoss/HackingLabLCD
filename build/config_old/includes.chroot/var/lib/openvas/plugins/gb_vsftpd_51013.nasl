###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vsftpd_51013.nasl 13 2013-10-27 12:16:33Z jan $
#
# vsftpd '__tzfile_read()' Function Heap Based Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
tag_summary = "vsftpd is prone to a buffer-overflow vulnerability because
it fails to perform adequate boundary checks on user-
supplied data.

Attackers may leverage this issue to execute arbitrary code in the
context of the application. Failed attacks will cause denial-of-
service conditions.

vsftpd 2.3.4 is affected; other versions may also be vulnerable.";


if (description)
{
 script_id(103362);
 script_bugtraq_id(51013);
 script_version ("$Revision: 13 $");
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

 script_name("vsftpd '__tzfile_read()' Function Heap Based Buffer Overflow Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51013");
 script_xref(name : "URL" , value : "http://dividead.wordpress.com/tag/heap-overflow/");
 script_xref(name : "URL" , value : "http://vsftpd.beasts.org/");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-12-13 10:23:55 +0100 (Tue, 13 Dec 2011)");
 script_description(desc);
 script_summary("Determine if installed vsftpd version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("ftp_func.inc");
include("version_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(get_kb_item('ftp/'+port+'/broken'))exit(0);

if(!get_port_state(port)){
  exit(0);
}

if(!banner = get_ftp_banner(port)) exit(0);
if("vsftpd" >!< tolower(banner))exit(0);

version = eregmatch(pattern:"vsftpd ([0-9.]+)", string:   tolower(banner));
if(isnull(version[1]))exit(0);
vers = version[1];

if(!isnull(vers)) {

    if(version_is_equal(version:vers, test_version:"2.3.4") ) {
        security_hole(port: port);
        exit(0);

    }
}

exit(0);
