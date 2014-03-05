###############################################################################
# OpenVAS Vulnerability Test
# $Id: sendmail_expn.nasl 43 2013-11-04 19:51:40Z jan $
#
# VRFY and EXPN request check.
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
tag_solution = "Disable VRFY and/or EXPN on your Mailserver. 
  For postfix add 'disable_vrfy_command=yes' in 'main.cf'. 
  For Sendmail add the option 'O PrivacyOptions=goaway'.";
tag_summary = "The Mailserver on this host answers to VRFY and/or EXPN requests.
  VRFY and EXPN ask the server for information about an address. They are
  inherently unusable through firewalls, gateways, mail exchangers for part-time
  hosts, etc. OpenVAS suggests that, if you really want to publish this type of
  information, you use a mechanism that legitimate users actually know about,
  such as Finger or HTTP.";

 desc = "

 Summary:
 " + tag_summary + "

 Solution:
 " + tag_solution;


if (description)
{
 script_id(100072);
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-03-23 19:32:33 +0100 (Mon, 23 Mar 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Check if Mailserver answer to VRFY and EXPN requests");  

 script_description(desc);
 script_summary("Checks if Mailserver answer to VRFY and EXPN requests");
 script_category(ACT_GATHER_INFO);
 script_family("SMTP problems");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_exclude_keys("SMTP/wrapped");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://cr.yp.to/smtp/vrfy.html");
 exit(0);
}

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if (!port) port = 25;
if(!get_port_state(port))exit(0);

soctcp25 = open_sock_tcp(port);
if(!soctcp25)exit(0);

bannertxt = smtp_recv_banner(socket:soctcp25);
send(socket:soctcp25, data:string("EHLO ",this_host(),"\r\n"));
ehlotxt = smtp_recv_line(socket:soctcp25);

if(("250" >< ehlotxt) || ("550" >< ehlotxt)) {
#vrfy
 send(socket: soctcp25, data:string("VRFY root\r\n")); 
 vrfy_txt = smtp_recv_line(socket:soctcp25);

 if(("250" >< vrfy_txt) || ("251" >< vrfy_txt) || ("550" >< vrfy_txt) || ("252" >< vrfy_txt)) {
  if(
     !egrep(pattern:"Administrative prohibition", string: vrfy_txt) &&
     !egrep(pattern:"Access Denied", string: vrfy_txt) &&
     !egrep(pattern:"not available", string: vrfy_txt) &&
     !egrep(pattern:"String does not match anything", string: vrfy_txt) &&
     !egrep(pattern:"Cannot VRFY user", string: vrfy_txt) &&
     !egrep(pattern:"VRFY disabled", string: vrfy_txt) &&
     !egrep(pattern:"252 send some mail, i'll try my best", string: vrfy_txt)
    ) {
       set_kb_item(name:"SMTP/vrfy",value:TRUE); 
       VRFY = TRUE;
       TEXT += string("'VRFY root' produces the following answer: ", vrfy_txt,"\n");
  }  
 }  
#expn
 send(socket: soctcp25, data:string("EXPN root\r\n"));
 expn_txt =  smtp_recv_line(socket:soctcp25);

 if(("250" >< expn_txt) || ("550" >< expn_txt)) {

   if(
     !egrep(pattern:"Administrative prohibition", string: vrfy_txt) &&
     !egrep(pattern:"Access Denied", string: vrfy_txt) &&
     !egrep(pattern:"EXPN not available", string: vrfy_txt) &&
     !egrep(pattern:"lists are confidential", string: vrfy_txt) &&
     !egrep(pattern:"not available", string: vrfy_txt)
    ) {
       set_kb_item(name:"SMTP/expn",value:TRUE);
       EXPN = TRUE;
       TEXT += string("'EXPN root' produces the following answer: ", expn_txt , "\n");
  }
 }  
}  

close(soctcp25);

if(VRFY || EXPN) {
 desc = string(desc, "\n\nDetails:\n\n", TEXT);
 security_warning(port:port,data:desc);
 exit(0);
}


exit(0);
