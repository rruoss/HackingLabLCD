###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lexmark_printers_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# Lexmark Printer Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
tag_summary = "Detection of Lexmark Printers.

The script sends a connection request to the remote host and
attempts to detect if the remote host is a Lexmark printer.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103685";   

if (description)
{
 
 script_tag(name:"risk_factor", value:"None");
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version ("$Revision: 18 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-03-28 11:31:24 +0100 (Thu, 28 Mar 2013)");
 script_name("Lexmark Printer Detection");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);

 script_summary("Checks for Lexmark Printer");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("lexmark_printers.inc");
include("host_details.inc");
include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

urls = lexmark_detect_urls;

foreach url(keys(urls)) {

  pattern = url;
  url = urls[url];

  req = http_get(item:url, port:port);
  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if(lex = eregmatch(pattern:pattern, string: buf, icase:TRUE)) {

    if(!isnull(lex[1])) {

      concluded = lex[0];
      model     = lex[1];

      chomp(model);

      set_kb_item(name:"target_is_printer", value:1);
      set_kb_item(name:"lexmark_printer/installed", value:1);
      set_kb_item(name:"lexmark_printer/port", value: port);
      set_kb_item(name:"lexmark_model", value:model);

      cpe_model = tolower(model);

      cpe = 'cpe:/h:lexmark:' + cpe_model;
      cpe = str_replace(string:cpe,find:" series", replace:"");

      register_product(cpe:cpe, location:port + '/tcp', nvt:SCRIPT_OID, port:port);
 
      log_message(data: "The remote Host is a Lexmark " + model + " printer device.\nCPE: " + cpe + "\nConcluded: " + concluded, port:port);
      exit(0);

    }  

  }  

}  

exit(0);