###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xerox_printers_default_credentials.nasl 11 2013-10-27 10:12:02Z jan $
# OVAS-B-A10
# Xerox Printer Default Account Authentication Bypass Vulnerability
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
# of the License, or (at your option) any later version.
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
tag_summary = "The remote Xerox Printer is prone to a default account
authentication bypass vulnerability. This issue may be
exploited by a remote attacker to gain access to sensitive information
or modify system configuration without requiring authentication.";


tag_solution = "Ask the Vendor for updates.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103649";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Xerox Printer Default Account Authentication Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.h-online.com/security/news/item/Report-Thousands-of-embedded-systems-on-the-net-without-protection-1446441.html");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-01-30 15:51:27 +0100 (Wed, 30 Jan 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to login into the remote printer");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_xerox_printer_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("xerox_printer/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("xerox_printers.inc");
include("http_func.inc");

port = get_http_port(default:80);

model = get_kb_item("xerox_model");
if(!model)exit(0);

ret = check_xerox_default_login(model:model); 

if(ret) {

  if(ret == 1) {
    message = 'It was possible to login into the remote Xerox ' + model + ' with user "' + last_user + '" and password "' + last_pass + '"\n';
  } 
  
  else if(ret == 2) {
    message = 'The remote Xerox ' + model + ' is not protected by a username and password.\n';
  }

  security_hole(port:port, data:message);
  exit(0);

}

exit(99);
  
