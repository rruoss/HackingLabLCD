###############################################################################
# OpenVAS Vulnerability Test
# $Id: novell_edirectory_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Novell eDirectory Detection
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
tag_summary = "Detection of Novell eDirectory.

The script detects the service of Novell eDirectory on remote host
and sets the KB.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100339";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-11-06 12:41:10 +0100 (Fri, 06 Nov 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"detection", value:"remote probe");
 script_name("Novell eDirectory Detection");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_summary("Checks for the presence of Novell eDirectory");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
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
include("cpe.inc");
include("host_details.inc");

## Variables Initialization
port = 0;
req = "";
soc = 0;
len = "";
data = "";
str = "";
cpe = "";
version = "";
linenumber = "";

## Constant values

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

if("eDirectory" >< str ) {
  version = eregmatch(string:str, pattern:"LDAP Agent for Novell eDirectory ([0-9.]+ ([^#]+)?)");
  if(!isnull(version[1])) {
    set_kb_item(name:string("ldap/",port,"/eDirectory"), value:version[1]);
    set_kb_item(name:"eDirectory/installed",value:TRUE);
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:version[1], exp:"^([0-9.]+\.[0-9])\.? ?([a-z0-9]+)?", base:"cpe:/a:novell:edirectory:");
    if(isnull(cpe))
       cpe = "cpe:/a:novell:edirectory";

       register_product(cpe:cpe, location:"/", nvt:SCRIPT_OID, port:port);

       log_message(data: build_detection_report(app:"Novell eDirectory",
                                                version: version[1],
                                                install:"/",
                                                cpe:cpe,
                                                concluded: dump[max_index(dump)-1]),
                                                port: port);

  }
}

exit(0);
