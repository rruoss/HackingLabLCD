###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Check Sendmail Configuration
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
#
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Check Sendmail Configuration.
  
  The Script test the SMTP Sendmail Server if the commands, 
  debug, vrxf and expn avaible.";

if(description)
{
  script_id(96098);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2010-06-21 10:39:50 +0200 (Mon, 21 Jun 2010)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Check Sendmail Configuration");

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Check Sendmail Configuration");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("smtpserver_detect.nasl");
#  script_require_keys("SMTP/sendmail");
#  script_exclude_keys("SMTP/wrapped");
#  script_require_ports("Services/smtp", 25);

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("smtp_func.inc");

sendmail = get_kb_item("SMTP/sendmail");

if (!sendmail){
  sendmaildebug = "nosendmail";
  sendmailvrfy = "nosendmail";
  sendmailexpn = "nosendmail";
}
else{
  port = get_kb_item("Services/smtp");
  if(!port)port = 25;
  if(!get_port_state(port)){ 
    sendmaildebug = "noport";
    sendmailvrfy = "noport";
    sendmailexpn = "noport";
  } 
  else if(get_kb_item("SMTP/wrapped")){
    sendmaildebug = "nosmtp";
    sendmailvrfy = "nosmtp";
    sendmailexpn = "nosmtp";
  }
  else {


    soc = open_sock_tcp(port);
    if(soc)
     {
      b = smtp_recv_banner(socket:soc);
      s = string("debug\r\n");
      send(socket:soc, data:s);
      r = recv_line(socket:soc, length:1024);
      r = tolower(r);
      if(("200 debug set" >< r))sendmaildebug = "yes";
      else sendmaildebug = "no";
      send(socket: soc, data:string("quit\r\n"));
      close(soc);
     }
     else sendmaildebug = "nosoc";
#############

      soc = open_sock_tcp(port);
      if(soc){
      b = smtp_recv_banner(socket:soc);
      send(socket:soc, data:string("EHLO ",this_host(),"\r\n"));
      ehlotxt = smtp_recv_line(socket:soc);

      if(("250" >< ehlotxt) || ("550" >< ehlotxt)) {
       send(socket: soc, data:string("VRFY root\r\n")); 
       vrfy_txt = smtp_recv_line(socket:soc);
       if(("250" >< vrfy_txt) || ("251" >< vrfy_txt) || ("550" >< vrfy_txt)) {
        if(
           !egrep(pattern:"Administrative prohibition", string: vrfy_txt) &&
           !egrep(pattern:"Access Denied", string: vrfy_txt) &&
           !egrep(pattern:"not available", string: vrfy_txt) &&
           !egrep(pattern:"String does not match anything", string: vrfy_txt)
          ) {
              sendmailvrfy = "yes";
            }
            else sendmailvrfy = "no";  
       }  
       send(socket: soc, data:string("EXPN root\r\n"));
       expn_txt =  smtp_recv_line(socket:soc);
       if(("250" >< expn_txt) || ("550" >< expn_txt)) {

         if(
           !egrep(pattern:"Administrative prohibition", string: expn_txt) &&
           !egrep(pattern:"Access Denied", string: expn_txt) &&
           !egrep(pattern:"not available", string: expn_txt)
          ) {
              sendmailexpn = "yes";
            }
        else sendmailexpn = "no";
       }  
      } 
      send(socket: soc, data:string("quit\r\n"));
      close(soc);
    }
    else{
      sendmailvrfy = "nosoc";
      sendmailexpn = "nosoc";
    }
  }
} 
######################

if (!sendmaildebug) sendmaildebug = "error";
if (!sendmailvrfy) sendmailvrfy = "error";
if (!sendmailexpn) sendmailexpn = "error";

set_kb_item(name: "GSHB/SENDMAIL/DEBUG", value:sendmaildebug);
set_kb_item(name: "GSHB/SENDMAIL/VRFX", value:sendmailvrfy);
set_kb_item(name: "GSHB/SENDMAIL/EXPN", value:sendmailexpn);
exit(0);


