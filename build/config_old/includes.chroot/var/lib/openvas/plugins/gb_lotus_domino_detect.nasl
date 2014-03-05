###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lotus_domino_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Lotus Domino Detection
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
tag_summary = "This host is running Lotus Domino. The Lotus Domino server can provide
multiple services. The core services include:

* Email server (supporting Lotus Notes, POP3, IMAP, web browser and
  Outlook clients and SMTP support)
* Applications server (the Lotus Notes client provides the runtime)
* Web server (Lotus Notes data or other surfaced via a web browser)
* Database server (Notes Storage Facility)
* Directory server (LDAP)";


# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 
 script_id(100597);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2010-04-22 20:18:17 +0200 (Thu, 22 Apr 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Lotus Domino Detection");
 
 script_description(desc);
 script_summary("Checks for the presence of Lotus Domino");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/smtp", 25, "Services/pop3", 110, "Services/imap", 143);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www-01.ibm.com/software/lotus/notesanddomino/");
 exit(0);
}

include("smtp_func.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("global_settings.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100597";
SCRIPT_DESC = "Lotus Domino Detection";

domino_ver = FALSE;

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if (get_port_state(port)) {
  
  banner = get_smtp_banner(port:port);
  if(banner && "Lotus Domino Release" >< banner) {

    version = eregmatch(pattern:"Lotus Domino Release ([0-9][^)]+)", string:banner);
    if(!isnull(version[1]))domino_ver = version[1];

  }  
}  

if(!domino_ver) {

  port = get_kb_item("Services/imap");
  if (!port) port = 143;
  if (get_port_state(port)) {

    banner = get_imap_banner(port:port);
    if(banner && "Domino IMAP4 Server Release" >< banner) {

      version = eregmatch(pattern:"Domino IMAP4 Server Release ([0-9][^ ]+)", string:banner);
      if(!isnull(version[1]))domino_ver = version[1];

    }  
  }  
}  

if(!domino_ver) {

  port = get_kb_item("Services/pop3");
  if (!port) port = 110;
  if (get_port_state(port)) {
  
    banner = get_pop3_banner(port:port);
    if(banner && "Lotus Notes POP3 server version Release" >< banner) {

      version = eregmatch(pattern:"Lotus Notes POP3 server version Release ([0-9][^ ]+)", string:banner);
      if(!isnull(version[1]))domino_ver = version[1];

    }  
  }  
}  

if(domino_ver) {

  register_host_detail(name:"App", value:string("cpe:/a:lotus:domino_server:", domino_ver), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
  set_kb_item(name:string("Domino/Port/"), value:port);
  set_kb_item(name:string("Domino/Version"),value: domino_ver);

  info  = string("notesanddomino/\n\nLotus Domino Version (");
  info += string(domino_ver);
  info += string(") was detected on the remote host.\n");

  desc = ereg_replace(
          string:desc,
          pattern:"notesanddomino/$",
          replace:info
      );

  if(report_verbosity > 0) {
    security_note(port:port,data:desc);
  }  
}  
