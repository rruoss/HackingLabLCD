###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_canon_printers_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# Canon Printer Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
tag_summary = "Detection of Canon Printers.

The script sends a connection request to the remote host and attempts
to detect if the remote host is a Canon printer.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803719";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version ("$Revision: 18 $");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-20 13:42:47 +0530 (Thu, 20 Jun 2013)");
  script_name("Canon Printer Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

 script_summary("Checks for Canon Printer");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
 exit(0);
}


include("http_func.inc");
include("host_details.inc");


port = "";
req = "";
buf = "";
firm_ver = "";
printer_model = "";

port = get_http_port(default:80);
if(!port){
  port = 80;
}

if(!get_port_state(port)){
  exit(0);
}

req = http_get(item:"/index.html", port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

## Confirm the application
if('>Canon' >< buf && ">Copyright CANON INC" ><  buf && "Printer" >< buf)
{
   set_kb_item(name:"target_is_printer", value:1);
   set_kb_item(name:"canon_printer/installed", value:1);
   set_kb_item(name:"canon_printer/port", value: port);

   ## Get the model name
   printer_model = eregmatch(pattern:">(Canon.[A-Z0-9]+).[A-Za-z]+<", string: buf);
   if(printer_model[1])
   {
     set_kb_item(name:"canon_printer_model", value:printer_model[1]);

     cpe_printer_model = tolower(printer_model[1]);
     cpe = 'cpe:/h:canon:' + cpe_printer_model;
     cpe = str_replace(string:cpe,find:" ", replace:"_");

     ## Get the Firmware version
     firm_ver = eregmatch(pattern:"nowrap>([0-9.]+)</td>", string: buf);
     if(firm_ver[1])
     {
       set_kb_item(name:"canon_printer/firmware_ver", value: firm_ver[1]);
       cpe = cpe + ":" + firm_ver[1];
     }

     register_product(cpe:cpe, location:port + '/tcp', nvt:SCRIPT_OID, port:port);

     log_message(data: "The remote Host is a  " + printer_model[1] +
                 " printer device.\nCPE: " + cpe + "\nConcluded: " +
                 printer_model[1], port:port);
      exit(0);

  }
}
