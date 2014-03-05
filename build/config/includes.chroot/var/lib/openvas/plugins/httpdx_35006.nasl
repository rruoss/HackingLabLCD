###############################################################################
# OpenVAS Vulnerability Test
# $Id: httpdx_35006.nasl 15 2013-10-27 12:49:54Z jan $
#
# httpdx Multiple Commands Remote Buffer Overflow Vulnerabilities
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
################################################################################

include("revisions-lib.inc");
tag_summary = "The 'httpdx' program is prone to multiple remote buffer-overflow
   vulnerabilities because the application fails to perform adequate
   boundary-checks on user-supplied data.

   An attacker can exploit these issues to execute arbitrary code
   within the context of the affected application. Failed exploit
   attempts will result in a denial-of-service condition.

   These issues affect httpdx 0.5b; other versions may also be
   affected.";


if(description)
{
  script_id(100210);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-24 11:22:37 +0200 (Sun, 24 May 2009)");
  script_bugtraq_id(35006);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("httpdx Multiple Commands Remote Buffer Overflow Vulnerabilities");

  desc = "

  Summary:
  " + tag_summary;


  script_description(desc);
  script_summary("Determine if httpdx is vulnerable to buffer-overflow.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("find_service.nasl","secpod_ftp_anonymous.nasl","ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/35006");
  exit(0);
}

include("ftp_func.inc");

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

if(get_kb_item('ftp/'+port+'/broken'))exit(0);

if(!get_port_state(ftpPort)){
  exit(0);
}

if( ! banner = get_ftp_banner(port:ftpPort) ) exit(0);

if( "httpdx" >< banner ) {

  if( safe_checks() ) {

   if( egrep(pattern:"httpdx 0.5 beta", string: banner) ) {

      security_hole(port:ftpPort);
      exit(0);
   }  

  } else {

     soc = open_sock_tcp(ftpPort);
   
     if(!soc){
       exit(0);
     }

     user = crap(length: 100000);
     pass = "bla";

     ftp_log_in(socket:soc, user:user, pass:pass);
     close(soc);

     sleep(2);

     soc1 = open_sock_tcp(ftpPort);

     if(!soc1){
	security_hole(port:ftpPort);
	exit(0);
     } 
  }
}

exit(0);
