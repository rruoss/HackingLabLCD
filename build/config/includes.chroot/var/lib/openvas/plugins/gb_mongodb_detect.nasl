###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongodb_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# MongoDB Detection
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100747";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 44 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-08-06 15:09:20 +0200 (Fri, 06 Aug 2010)");
  script_tag(name:"detection", value:"remote probe");
  script_name("MongoDB Detection");

  tag_summary =
"This host is running MongoDB database.

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

 script_description(desc);
 script_xref(name : "URL" , value : "http://www.mongodb.org");
 script_summary("Checks for the presence of MongoDB");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports(27017);
 exit(0);
}

include("misc_func.inc");
include("dump.inc");
include("cpe.inc");
include("host_details.inc");
include("global_settings.inc");

## Variable Initialization
dbPort = "";
vers = "";
buf = "";

function bin2string (ddata)
{
  local_var tmp, i, j, line, linenumber, len, data, c;

  len = strlen (ddata);
  linenumber = len / 16;

  for (i = 0; i <= linenumber; i++)
  {
    line = line2string (line:i, linenumber:len);
    data = "";

    for (j = 0; j < 16; j++)
    {
      if ( (i*16+j) < len )
      {
        c = ddata[i*16+j];

        if (isprint (c:c))
        data += c;
      }
    }
    tmp += string (data);
  }
  return tmp;
}

dbPort = 27017;
if(!get_port_state(dbPort))exit(0);;

soc = open_sock_tcp(dbPort);
if(!soc)exit(0);

data = raw_string(
   0x3c,0x00,0x00,0x00,0xff,0x0d,0xc2,0xc0,0xff,0xff,0xff,0xff,0xd4,0x07,0x00,0x00,
   0x00,0x00,0x00,0x00,0x61,0x64,0x6d,0x69,0x6e,0x2e,0x24,0x63,0x6d,0x64,0x00,0x00,
   0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x15,0x00,0x00,0x00,0x10,0x77,0x68,0x61,0x74,
   0x73,0x6d,0x79,0x75,0x72,0x69,0x00,0x01,0x00,0x00,0x00,0x00);

send(socket:soc,data:data);
buf = recv(socket:soc, length:1024);

if("you" >< buf && "ok" >< buf && this_host() >< buf)
{
  register_service(port:dbPort, ipproto:"tcp", proto:"mongodb");
  vers = string("unknown");

  data = raw_string(
       0x3f,0x00,0x00,0x00,0x00,0x0e,0xc2,0xc0,0xff,0xff,0xff,0xff,0xd4,0x07,0x00,0x00,
       0x00,0x00,0x00,0x00,0x61,0x64,0x6d,0x69,0x6e,0x2e,0x24,0x63,0x6d,0x64,0x00,0x00,
       0x00,0x00,0x00,0xff,0xff,0xff,0xff,0x18,0x00,0x00,0x00,0x01,0x62,0x75,0x69,0x6c,
       0x64,0x69,0x6e,0x66,0x6f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xf0,0x3f,0x00);

  send(socket:soc,data:data);
  buf = recv(socket:soc, length:1024);
  close(soc);

  if("version" >< buf)
  {
    txt = bin2string(ddata:buf);
    version = eregmatch(pattern:"version([0-9.]+)", string:txt);
    if(!isnull(version[1]))
    {
      vers = version[1];

      set_kb_item(name:string("mongodb/installed"),value:TRUE);
      set_kb_item(name:string("mongodb/",dbPort,"/version"),value:vers);

      ## run depending nvts only if report_paranoia is > 1 to avoid false positives against backports
      if (report_paranoia > 1 ) {
        set_kb_item(name:'mongodb/paranoia', value:TRUE);
      }

      cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:mongodb:mongodb:");
      if(isnull(cpe))
        cpe = 'cpe:/a:mongodb:mongodb';

      register_product(cpe:cpe, location:dbPort, nvt:SCRIPT_OID, port:dbPort);

      log_message(data: build_detection_report(app:"MongoDB", version:vers,
                                               install:dbPort + "/tcp", cpe:cpe, concluded: vers),
                                               port:dbPort);
    }
  }
}
else {
  close(soc);
}

exit(0);
