# OpenVAS Vulnerability Test
# $Id: smtpserver_detect.nasl 41 2013-11-04 19:00:12Z jan $
# Description: SMTP Server type and version
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_solution = "Change the login banner to something generic.";

tag_summary = "This detects the SMTP Server's type and version by connecting to
the server and processing the buffer received.  This information gives potential
attackers additional information about the system they are attacking. Versions
and Types should be omitted where possible.";

if(description)
{
 script_id(10263);
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");

 script_name("SMTP Server type and version");

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 script_summary("SMTP Server type and version");

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 1999 SecuriTeam");
 script_family("General");

 script_dependencies("find_service_3digits.nasl");
 script_require_ports("Services/smtp", 25);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

#
# The script code starts here
#
include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if (!port) port = 25;

if (get_port_state(port))
{
 soctcp25 = open_sock_tcp(port);

 if (soctcp25)
 {
  bannertxt = smtp_recv_banner(socket:soctcp25);

  if(!bannertxt){
        set_kb_item(name:"SMTP/wrapped", value:TRUE);
        close(soctcp25);
        exit(0);
        }

  if( ! ("220" >< bannertxt)) {
    # Doesn't look like SMTP...
    close(soctcp25);
    exit(0);
  }

  send(socket:soctcp25, data:string("EHLO ",this_host(),"\r\n"));
  ehlotxt = smtp_recv_line(socket:soctcp25);
  send(socket: soctcp25, data:string("HELP\r\n"));
  helptxt = smtp_recv_line(socket:soctcp25);
  send(socket: soctcp25, data:string("NOOP\r\n"));
  nooptxt = smtp_recv_line(socket:soctcp25);
  send(socket: soctcp25, data:string("RSET\r\n"));
  rsettxt = smtp_recv_line(socket:soctcp25);
  send(socket: soctcp25, data:string("QUIT\r\n"));
  quittxt = smtp_recv_line(socket:soctcp25);

  #display("banner=[",bannertxt,"]\nehlo=[",ehlotxt,"]\nhelp=[",helptxt,"]\nnoop=[",nooptxt,"]\nrset=[",rsettxt,"]\nquit=[",quittxt,"]\n");

  if (("Exim" >< bannertxt) ||
      (("closing connection" >< quittxt) && ("OK" >< nooptxt) && ("Commands supported:" >< helptxt)))
  {
   set_kb_item(name:"SMTP/exim", value:TRUE);
   guess = "Exim";
   str = egrep(pattern:" Exim ", string:bannertxt);
   if(str) {
     str=ereg_replace(pattern:"^.*Exim ([0-9\.]+) .*$", string:str, replace:"\1");
     guess=string("Exim version ",str);
   }
  }

  if (("qmail" >< bannertxt) || ("qmail" >< helptxt))
  {
   set_kb_item(name:"SMTP/qmail", value:TRUE);
   guess = "Qmail";
  }

  if ("Postfix" >< bannertxt)
  {
   set_kb_item(name:"SMTP/postfix", value:TRUE);
   guess = "Postfix";
  }

  if(("Sendmail" >< bannertxt) || ("This is sendmail version" >< helptxt) || ("sendmail-bugs@sendmail.org" >< helptxt))
  {
   set_kb_item(name:"SMTP/sendmail", value:TRUE);
   guess = "Sendmail";
   str = egrep(pattern:"This is sendmail version ", string:helptxt);
   if(str) {
     str=ereg_replace(pattern:".*This is sendmail version ", string:str, replace:"");
     guess=string("Sendmail version ",str);
   }
  }

  if("XMail " >< bannertxt)
  {
   set_kb_item(name:"SMTP/xmail", value:TRUE);
   guess = "XMail";
  }

  if(egrep(pattern:".*nbx.*Service ready.*", string:bannertxt))
  {
   set_kb_item(name:"SMTP/3comnbx", value: TRUE);
  }

  if(("Microsoft Exchange Internet Mail Service" >< bannertxt) ||
     ("NTLM LOGIN" >< bannertxt) ||
     ("Microsoft ESMTP MAIL Service, Version: 5" >< bannertxt) ||
     ("Microsoft SMTP MAIL" >< bannertxt) ||
     (("This server supports the following commands" >< helptxt) && ("End of HELP information" >< helptxt) &&
     ("Service closing transmission channel" >< quittxt) && ("Resetting" >< rsettxt)))
  {
   set_kb_item(name:"SMTP/microsoft_esmtp_5", value:TRUE);
   guess = "Microsoft Exchange version 5.X";
   str = egrep(pattern:" Version: ", string:bannertxt);
   if(str) {
     str=ereg_replace(pattern:".* Version: ", string:str, replace:"");
     guess=string("Microsoft Exchange version ",str);
   }
  }

  if(("ZMailer Server" >< bannertxt) ||
    (("This mail-server is at Yoyodyne Propulsion Inc." >< helptxt) && # Default help text.
     ("Out" >< quittxt) && ("zmhacks@nic.funet.fi" >< helptxt))) {
   set_kb_item(name:"SMTP/zmailer", value:TRUE);
   guess = "ZMailer";
   str = egrep(pattern:" ZMailer ", string:bannertxt);
   if(str) {
     str=ereg_replace(pattern:"^.*ZMailer Server ([0-9a-z\.\-]+) .*$", string:str, replace:"\1");
     guess=string("ZMailer version ",str);
   }
  }

  if("CheckPoint FireWall-1" >< bannertxt)
  {
   set_kb_item(name:"SMTP/firewall-1", value: TRUE);
   guess="CheckPoint FireWall-1";
  }

  if(("InterMail" >< bannertxt) ||
    (("This SMTP server is a part of the InterMail E-mail system" >< helptxt) &&
    ("Ok resetting state." >< rsettxt) && ("ESMTP server closing connection." >< quittxt))) {
   set_kb_item(name:"SMTP/intermail", value:TRUE);
   guess = "InterMail";
   str = egrep(pattern:"InterMail ", string:bannertxt);
   if(str) {
     str=ereg_replace(pattern:"^.*InterMail ([A-Za-z0-9\.\-]+).*$", string:str, replace:"\1");
     guess=string("InterMail version ",str);
   }
  }

  if(("Lotus Domino" >< bannertxt) ||
    (("pleased to meet you" >< ehlotxt) && ("Enter one of the following commands" >< helptxt) &&
    ("Reset state" >< rsettxt) && ("SMTP Service closing transmission channel" >< quittxt))) {
   set_kb_item(name:"SMTP/domino", value:TRUE);
   guess = "Domino";
   str = egrep(pattern:"Lotus Domino ", string:bannertxt);
   if(str) {
     str=ereg_replace(pattern:"^.*\(Lotus Domino Release ([0-9\.\-]+)\).*$", string:str, replace:"\1");
     guess=string("Lotus Domino version ",str);
   }
  }

  if ("mail rejector" >< bannertxt ||
      match(pattern: "*snubby*", string: ehlotxt, icase: 1))
  {
    set_kb_item(name: "SMTP/snubby", value: TRUE);
    set_kb_item(name: "SMTP/wrapped", value: TRUE);
    guess = "Snubby Mail Rejector (not a real server)";
    security_note(port: port, data: "
Verisign mail rejector appears to be running on this port.
You probably mistyped your hostname and OpenVAS is scanning the wildcard
address in the .COM or .NET domain.

Solution : enter a correct hostname");
  }

  data = string("Remote SMTP server banner :\n",  bannertxt);
  if (guess) {
   data=string(data, "\n\n\nThis is probably: ",guess);
   security_note(port:port, data:data);
  } else {
    log_message(port:port, data:data);
  }
 close(soctcp25);
 }

}
