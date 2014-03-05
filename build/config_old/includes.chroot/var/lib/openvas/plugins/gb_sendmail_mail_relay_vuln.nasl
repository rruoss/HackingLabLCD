###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sendmail_mail_relay_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# SendMail Mail Relay Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Upgrade to the latest version of Linuxconf version 1.29r1 or later
  For updates refer to http://www.solucorp.qc.ca/linuxconf/

  For IBM AIX, apply the patch from below link
  ftp://aix.software.ibm.com/aix/efixes/security/sendmail_3_mod.tar.Z";

tag_impact = "Successful exploitation will allow attackers to send email messages outside
  of the served network. This could result in unauthorized messages being sent
  from the vulnerable server.
  Impact Level: Application/System";
tag_affected = "Linuxconf versions 1.24 r2, 1.2.5 r3
  Linuxconf versions 1.24 r2, 1.2.5 r3 on Conectiva Linux 6.0 through 8
  IBM AIX versions 4.3, 4.3.1, 4.3.2, 4.3.3, 5.1, 5.1 L, 5.2";
tag_insight = "The flaw is due to an error in the mailconf module in Linuxconf which
  generates the Sendmail configuration file (sendmail.cf) and configures
  Sendmail to run as an open mail relay, which allows remote attackers to send
  Spam email.";
tag_summary = "This host is installed with SendMail and is prone to mail relay
  vulnerability.";

if(description)
{
  script_id(802194);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2002-1278", "CVE-2003-0285");
  script_bugtraq_id(6118, 7580);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-15 12:51:12 +0530 (Tue, 15 Nov 2011)");
  script_name("SendMail Mail Relay Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  script_xref(name : "URL" , value : "http://osvdb.org/6066");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/10554");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/6118/solution");

  script_description(desc);
  script_summary("check if SendMail is prone to open mail relay vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("SMTP problems");
  script_dependencies("smtpserver_detect.nasl","sendmail_expn.nasl","smtp_settings.nasl");
  script_require_ports("Services/smtp", 25);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("smtp_func.inc");
include("misc_func.inc");
include("network_func.inc");

## Get the SMTP port
port = get_kb_item("Services/smtp");
if(!port){
  port = 25;
}

## Get SMTP banner to confirm sendmail
banner = get_smtp_banner(port);
if(!banner || "Sendmail" >!< banner){
  exit(0);
}

## Get the domain
domain = get_kb_item("Settings/third_party_domain");
if(!domain){
  domain = 'example.com';
}

## Open the Socket
soc = smtp_open(port:port, helo:NULL);
if(!soc){
  exit(0);
}

## Source Name
src_name = this_host_name();
FROM = string('openvas@', src_name);
TO = string('openvas@', domain);

## Send normal request
send(socket:soc, data:strcat('EHLO ', src_name, '\r\n'));
ans = smtp_recv_line(socket:soc);
if("250" >!< ans){
  exit(0);
}

mail_from = strcat('MAIL FROM: <', FROM , '>\r\n');

send(socket:soc, data:mail_from);
recv = smtp_recv_line(socket:soc);

## Check if Domain of sender exists
if(!recv || recv =~ '^5[0-9][0-9]'){
  exit(0);
}

## Check for the receiver
mail_to = strcat('RCPT TO: <', TO , '>\r\n');
send(socket:soc, data:mail_to);

## Receive response
recv = smtp_recv_line(socket: soc);

if(recv =~ '^2[0-9][0-9]')
{
  data = string("data\r\n");
  send(socket:soc, data:data);
  data_rcv = smtp_recv_line(socket:soc);

  if(egrep(pattern:"3[0-9][0-9]", string:data_rcv))
  {
    ## Constuct and send mail
    send(socket:soc, data:string("OpenVAS-Relay-Test\r\n.\r\n"));
    mail_send = smtp_recv_line(socket:soc);

    ## Checking mail is accepted
    if("250" >< mail_send)
    {
      security_hole(port:port);
      smtp_close(socket:soc);
      exit(0);
    }
  }
}
smtp_close(socket: soc);
