###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_soliddb_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# SolidDB Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2011-04-07
#  - Updated to detect version 6.3.x
#  - Updated the version pattern match.
#  - Updated to according to new style on  2013-09-19
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100721";

if (description)
{

 script_oid(SCRIPT_OID);
 script_version("$Revision: 44 $");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2010-07-21 19:56:46 +0200 (Wed, 21 Jul 2010)");
 script_tag(name:"detection", value:"remote probe");
 script_name("SolidDB Detection");

 tag_summary =
"Detection of SolidDB.

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

 script_description(desc);
 script_xref(name : "URL" , value : "http://www.solidtech.com/en/products/relationaldatabasemanagementsoftware/embed.asp");
 script_summary("Checks for the presence of SolidDB");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/unknown", 1315);
 exit(0);
}


include("cpe.inc");
include("byte_func.inc");
include("misc_func.inc");
include("global_settings.inc");
include("host_details.inc");

## Variable Initialization
version = "";
port = "";
req = "";
ret = "";

port = get_unknown_svc(1315);
if(!port){
  port = 1315;
}

if(known_service(port:port)){
  exit(0);
}

## check Port State
if(!get_port_state(port)){
  exit(0);
}

## Create Socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

user = "DBA";
pass = raw_string(0x76, 0xce, 0xa5, 0x2d, 0x72, 0x4f, 0x6f, 0x02);
tcp = string("tcp ", get_host_name(), " ", port);

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

req = raw_string(0x02, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00) + mkdword(1) +
      mkdword(strlen(tcp)) + tcp + mkdword(strlen(user)) + user +
      mkdword(strlen(pass)) + pass + mkdword(4) + mkdword(3) +
      mkdword(2) + mkdword(1) + mkdword(1) + mkdword(0) +
      mkdword(strlen(id)+3) + raw_string(0x04) + mkword(strlen(id)) + id;

send(socket:soc, data:req);
ret = recv(socket:soc, length:128);

if(!ret || isnull(ret)){
  exit(0);
}

if((strlen(ret) == 35 || strlen(ret) >= 27) &&
    hexstr(substr(ret, 0, 6)) == "02000100000000" &&
    hexstr(substr(ret, 6, 7)) == "0001")
{
  register_service(port:port, proto:"soliddb");

  # try to get version. Only possible if default credentials not changed

  version_cmd = "version";
  vers = "unknown";
  a = getdword(blob:ret, pos:27);
  b = getdword(blob:ret, pos:31);

  req = raw_string(0x02, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00) + mkdword(2) + mkdword(a) +
        mkdword(b) + mkdword(0x012d) + mkdword(strlen(version_cmd)) + version_cmd;

  send(socket:soc, data:req);
  ret = recv(socket:soc, length:1024);
  if("solidDB" >< ret)
  {
    s = 19;
    while (l = getdword(blob:ret, pos:s))
    {
      if (s+4+l < strlen(ret))
      {
        version_string += substr(ret, s+4, s+4+l-1);
        s += l+4;
       } else {
           break;
         }
    }
  }

  if(version_string)
  {
    version = eregmatch(pattern:"([0-9.]+).?(Build [0-9]*)?", string: version_string);
    if(!isnull(version[1]))
    {
      vers = version[1];
      if(!isnull(version[2])) {
        vers += " " + version[2];
     }
    }
  }

  if(vers == "unknown")
  {
    set_kb_item(name:"IBM-soliddb/installed", value:TRUE);
    register_product(cpe:cpe, location:port + '/udp', nvt:SCRIPT_OID, port:port);

    log_message(data: build_detection_report(app:"IBM solidDB Server", version:vers,
                install:port + '/udp', cpe:"cpe:/a:ibm:soliddb", concluded: vers, port:port));
  }
  else
  {
    default_credentials = TRUE;
    set_kb_item(name:"IBM-soliddb/installed", value:TRUE);
    set_kb_item(name:string("soliddb/",port,"/version"), value: vers);

    ## if build version is requred you need to use the get_kb_item() instead of
    ## get_app_version() in vulnerable nvt.
    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:ibm:soliddb:");
    if(isnull(cpe))
        cpe = 'cpe:/a:ibm:soliddb';

    register_product(cpe:cpe, location:port + '/udp', nvt:SCRIPT_OID, port:port);

    log_message(data: build_detection_report(app:"IBM solidDB Server", version:vers,
                install:port + '/udp', cpe:cpe, concluded: vers, port:port));
  }

  if(default_credentials)
  {
     desc1 = string("The remote solidDB has default credentials set. You should ",
                    "change\nthis credentials as soon as possible.");
     log_message(port:port,data:desc1);
  }
  exit(0);
}
