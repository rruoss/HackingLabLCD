###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sap_maxdb_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# SAP MaxDB Detection
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
tag_summary = "This host is running SAP MaxDB. MaxDB is an ANSI SQL-92 (entry level) compliant
relational database management system (RDBMS) from SAP AG,";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 script_id(100540);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-17 21:52:47 +0100 (Wed, 17 Mar 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("SAP MaxDB Detection");

 script_description(desc);
 script_summary("Checks for the presence of SAP MaxDB");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/unknown", 7210);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.sdn.sap.com/irj/sdn/maxdb");
 exit(0);
}

include("misc_func.inc");
include("global_settings.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100540";
SCRIPT_DESC = "SAP MaxDB Detection";

port = get_kb_item("Services/unknown");
if(!port)port=7210;

if(get_port_state(port)) {

  soc = open_sock_tcp(port);
  if(soc) {

    req = raw_string(
                    0x5A,0x00,0x00,0x00,0x03,0x5B,0x00,0x00,0x01,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,
                    0x00,0x00,0x04,0x00,0x5A,0x00,0x00,0x00,0x00,0x02,0x42,0x00,0x04,0x09,0x00,0x00,
                    0x00,0x40,0x00,0x00,0xD0,0x3F,0x00,0x00,0x00,0x40,0x00,0x00,0x70,0x00,0x00,0x00,
                    0x00,0x07,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x03,0x00,0x00,
                    0x07,0x49,0x33,0x34,0x33,0x32,0x00,0x04,0x50,0x1C,0x2A,0x03,0x52,0x01,0x03,0x72,
                    0x01,0x09,0x70,0x64,0x62,0x6D,0x73,0x72,0x76,0x00);

    send(socket:soc, data:req);
    buf = recv(socket:soc, length:2048);

    if("pdbmsrv" >!< buf) {
      close(soc);
      exit(0);
    }

    db_version = raw_string(0x28,0x00,0x00,0x00,0x03,0x3f,0x00,0x00,0x01,0x00,0x00,0x00,0xc0,0x0b,0x00,0x00,
                            0x00,0x00,0x04,0x00,0x28,0x00,0x00,0x00,0x64,0x62,0x6d,0x5f,0x76,0x65,0x72,0x73,
                            0x69,0x6f,0x6e,0x20,0x20,0x20,0x20,0x20);

    send(socket:soc, data:db_version);
    buf = recv(socket:soc, length:2048);
    close(soc);
  
    if("VERSION" >!< buf)exit(0);

    lines = split(buf, sep:'\n', keep:FALSE);

    foreach line (lines) {

      data = eregmatch(pattern:"^([^ =]+) *= *(.*)$", string:line);
    
      if(!isnull(data[1]) && !isnull(data[2])) {
     
        if(data[1] == "VERSION") {
          version = data[2];
          set_kb_item(name: string("sap_maxdb/",port,"/version"), value: version);
        }

        else if(data[1] == "BUILD") {
        
          build = eregmatch(pattern:"Build ([0-9-]+)", string: data[2]);
        
          if(!isnull(build[1])) {
            set_kb_item(name: string("sap_maxdb/",port,"/build"), value: build[1]);  
          }
        }

        info += string(data[1], " : ", data[2], "\n");

      }

    }

     if(version) {
       register_host_detail(name:"App", value:string("cpe:/a:sap:maxdb:",version), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
     } else {
       register_host_detail(name:"App", value:string("cpe:/a:sap:maxdb"), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
     }

     if(info) {
       info = string("\n\nInformation that was gathered:\n\n", info);
       desc = desc + info;
     }
 
      if(report_verbosity > 0) {
        security_note(port:port, data:desc);
      }

  }
}

exit(0);
