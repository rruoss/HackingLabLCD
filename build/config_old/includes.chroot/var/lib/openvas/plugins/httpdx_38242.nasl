###############################################################################
# OpenVAS Vulnerability Test
# $Id: httpdx_38242.nasl 14 2013-10-27 12:33:37Z jan $
#
# httpdx 'MKD' Command Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer
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
tag_summary = "The 'httpdx' program is prone to a directory-traversal vulnerability
because it fails to sufficiently sanitize user-supplied input.

Exploiting this issue allows an authenticated user to create
directories outside the FTP root directory, which may lead to
other attacks.

This issue affects httpdx 1.5; other versions may also be affected.";


if (description)
{
 script_id(100496);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-02-17 20:53:20 +0100 (Wed, 17 Feb 2010)");
 script_bugtraq_id(38242);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("httpdx 'MKD' Command Directory Traversal Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38242");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/httpdx/");

 script_description(desc);
 script_summary("Determine if httpdx is prone to a directory-traversal vulnerability");
 script_category(ACT_ATTACK);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","secpod_ftp_anonymous.nasl","ftpserver_detect_type_nd_version.nasl");
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
if("httpdx" >!< banner)exit(0);

version = eregmatch(pattern: "httpdx/([0-9.]+)", string:banner);
if(!isnull(version[1])) {
 
  if(version_is_equal(version: version[1], test_version: "1.5")) {
    security_hole(port:port);
    exit(0);
  }   
}  

exit(0);
