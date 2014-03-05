###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_informix_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# Informix Detection
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
tag_summary = "IBM Informix RDBMS is running at this port.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 script_id(100517);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-06 09:57:46 +0100 (Sat, 06 Mar 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Informix Detection");

 script_description(desc);
 script_summary("Checks for the presence of Informix");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","find_service2.nasl");
 script_require_ports("Services/unknown", 9088);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www-01.ibm.com/software/data/informix/");
 exit(0);
}

include("misc_func.inc");
include("byte_func.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100517";
SCRIPT_DESC = "Informix Detection";

port = get_kb_item("Services/unknown");
if(!port)port=9088;

username = "OPENVAS";
attempt = 3;

function read_data(data,pos) {

  local_var pos,data,str;
  global_var len;

  if(strlen(data) < pos)return FALSE;
  if(!l = substr(data, pos, pos))return FALSE;

  len = ord(l[0]);

  if(str = substr(data, pos+1, pos+1+len-2)) {
    return str;
  } else {
    return FALSE;
  }
}

if(get_port_state(port)) {

  soc = open_sock_tcp(port);
  if(soc) {

    req = raw_string(
 		   "sqAYABPQAAsqlexec ",
 		   username,
		   " -p",
		   username,
		   " 9.350  ",
		   "AAA#B000000 ",
		   "-d",
		   username,
		   " -fIEEEI ",
		   "DBPATH=//",
		   username,
		   " DBMONEY=$. ",
		   "CLIENT_LOCALE=en_US.8859-1 ",
 	           "SINGLELEVEL=no ",
		   "LKNOTIFY=yes ",
		   "LOCKDOWN=no ",
		   "NODEFDAC=no ",
		   "CLNT_PAM_CAPABLE=1 ",
		   ":AG0AAAA9b24AAAAAAAAAAAA9c29jdGNwAAAAAAABAAABPAAAAAAAAAAAc3FsZXh",
		   "lYwAAAAAAAAVzcWxpAAALAAAAAwAJbXlzZXJ2ZXIAAGsAAAAAAABSjQAAAAAABWt",
		   "pcmEAAAwvZGV2L3B0cy8xMgAACy9ob21lL21pbWUAAHQACAAAA.gAAABkAH8=",
		   0x00
		   );

    while (!buf && attempt--) {		 
      send(socket:soc, data:req);
      buf = recv(socket:soc, length:2048);
    }

    close(soc);

    if(strlen(buf) && strlen(buf) == getword(blob:buf, pos:0) && "IEEEI" >< buf && "lsrvinfx" >< buf) {
 
      register_service(port:port, proto:"informix", ipproto:"tcp");
      register_host_detail(name:"App", value:string("cpe:/a:ibm:informix_dynamic_server"), nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      info = string("\n\nHere is the gathered data:\n\n");

      data = strstr(buf, string(raw_string(0x00),"k",raw_string(0x00)));

      pos = int(15);
      if(fqdn = read_data(data:data,pos:pos)) {
        if (fqdn =~ "^[a-zA-Z0-9]")info += string("FQDN:         ", fqdn, "\n");
      }

      pos += len+2;
  
      if(host = read_data(data:data,pos:pos)) {
        if (host =~ "^[a-zA-Z0-9]")info += string("Hostname:     ", host, "\n");
      }
  
      pos += len+2;

      if(install = read_data(data:data,pos:pos)) {
        if (install =~ "^[/\:a-zA-Z0-9]")info += string("PATH:         ", install, "\n");
      }

      if(strlen(info) > 35) {
        desc = desc + info;
      }
      
      register_service(port:port, ipproto:"tcp", proto:"informix");
      security_note(port:port, data:desc);
    }  
  }
}


exit(0);
