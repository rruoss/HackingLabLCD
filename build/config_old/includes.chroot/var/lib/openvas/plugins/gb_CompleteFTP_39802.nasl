###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CompleteFTP_39802.nasl 14 2013-10-27 12:33:37Z jan $
#
# CompleteFTP Directory Traversal Vulnerability
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
tag_summary = "CompleteFTP is prone to a directory-traversal vulnerability because it
fails to sufficiently sanitize user-supplied input.

Exploiting this issue can allow an attacker to download arbitrary
files outside of the FTP server root directory. This may aid in
further attacks.

CompleteFTP 3.3.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100615);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-30 13:41:49 +0200 (Fri, 30 Apr 2010)");
 script_bugtraq_id(39802);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("CompleteFTP Directory Traversal Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39802");
 script_xref(name : "URL" , value : "http://www.enterprisedt.com/products/completeftp/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if remote CompleteFTP version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("ftpserver_detect_type_nd_version.nasl");
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

if( ! banner = get_ftp_banner(port) ) exit(0);
if("220-Complete FTP server" >!< banner)exit(0); 

version = eregmatch(pattern:"220 FTP Server v ([0-9.]+)", string: banner);
vers = version[1];

if( ! isnull(vers) ) {

    if( version_is_equal(version:vers, test_version:"3.3.0") ) {
        security_warning(port: port);
        exit(0);

    }
}

exit(0);
