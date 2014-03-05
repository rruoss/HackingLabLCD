###############################################################################
# OpenVAS Vulnerability Test
# $Id: sun_dir_server_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# Sun Java System Directory Server Detection
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
tag_summary = "This host is running Sun Java System Directory Server.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;
if (description)
{
 script_id(100437);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-12 12:22:08 +0100 (Tue, 12 Jan 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Sun Java System Directory Server Detection");

 script_description(desc);
 script_summary("Checks for the presence of Sun Java System Directory Server");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("ldap_detect.nasl");
 script_require_ports("Services/ldap", 389);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");
include("dump.inc");
include("global_settings.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100437";
SCRIPT_DESC = "Sun Java System Directory Server Detection";

port = get_kb_item("Services/ldap");

if(!port)exit(0);
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

req =
raw_string(0x30,0x25,0x02,0x01,0x01,0x63,0x20,0x04,0x00,0x0a,0x01,0x00,0x0a,0x01,0x00,0x02,
	   0x01,0x00,0x02,0x01,0x00,0x01,0x01,0x00,0x87,0x0b,0x6f,0x62,0x6a,0x65,0x63,0x74,
	   0x43,0x6c,0x61,0x73,0x73,0x30,0x00);

send(socket:soc, data:req);
data = recv(socket:soc, length:5000);

if( data == NULL ) exit(0);
close(soc);

len = strlen (data);

if(len <32)exit(0);

linenumber = len / 16;

for (i=0;i<=linenumber;i++) {
  for (j=0;j<16;j++) {
    if ((i*16+j)< len) {
      if(ord(data[i*16+j]) == "48" && ord(data[i*16+j+2]) == '4') {
        str += "#";
      } else {  
        c = data[i*16+j];
        if (isprint (c:c)) {
           str += c;
        }
       }
    }
  }
}

 if("Sun-Directory-Server" >< str ) {
    version = eregmatch(string:str, pattern:"Sun-Directory-Server/([0-9.]+([^#]+)?)");
    if(!isnull(version[1])) {
      set_kb_item(name:string("ldap/",port,"/SunJavaDirServer"), value:version[1]);
      register_host_detail(name:"App", value:string("cpe:/a:sun:java_system_directory_server:",version[1]), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
      info = string("\n\nSun Java System Directory Server Version '");
      info += string(version[1]);
      info += string("' was detected on the remote host\n");

      desc = desc + info;
    }
    if(report_verbosity > 0) {
      security_note(port:port,data:desc);
      exit(0);
    }
   }

exit(0);

