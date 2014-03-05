###############################################################################
# OpenVAS Vulnerability Test
# $Id: serv_u_37414.nasl 15 2013-10-27 12:49:54Z jan $
#
# Serv-U File Server User Directory Information Disclosure Vulnerability
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
tag_summary = "Serv-U File Server is prone to an unspecified information-disclosure
vulnerability.

Attackers can exploit this issue to harvest sensitive information that
may lead to further attacks.

Versions prior to SERV-U File Server 9.2.0.1 are vulnerable.";

tag_solution = "The vendor has released an update. Please see the references
for details.";

if (description)
{
 script_id(100410);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-12-21 12:36:27 +0100 (Mon, 21 Dec 2009)");
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
 script_cve_id("CVE-2009-4815");
 script_bugtraq_id(37414);
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Serv-U File Server User Directory Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 script_summary("Determine if Serv-U FTP Server version is < 9.2.0.1");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("gb_rhinosoft_serv-u_detect.nasl");
 script_require_ports("Services/ftp", 21);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37414");
 script_xref(name : "URL" , value : "http://www.serv-u.com/releasenotes/");
 script_xref(name : "URL" , value : "http://www.serv-u.com/");
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

if(!version = get_kb_item(string("ftp/", port, "/Serv-U"))) {
 if(!version = get_kb_item(string("Serv-U/FTP/Ver"))) {
  exit(0);
 }  
}  

if(!isnull(version[1])) {
  vers = version[1];
}  

if(!isnull(vers)) {
   if(vers =~ "^9\.") {
     if(version_is_less(version:vers, test_version:"9.2.0.1") ) {
         security_warning(port: port);
         exit(0);
     }
   }
}

exit(0);


