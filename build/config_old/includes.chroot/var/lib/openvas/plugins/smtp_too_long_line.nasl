# OpenVAS Vulnerability Test
# $Id: smtp_too_long_line.nasl 17 2013-10-27 14:01:43Z jan $
# Description: SMTP too long line
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
tag_summary = "Some antivirus scanners dies when they process an email with a 
too long string without line breaks.
Such a message was sent. If there is an antivirus on your MTA,
it might have crashed. Please check its status right now, as 
it is not possible to do it remotely";

# Credits: Berend-Jan Wever

if(description)
{
 script_id(11270);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "SMTP too long line";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Sends a too long single line to the MTA";
 script_summary(summary);
 
 script_category(ACT_DENIAL);
 
 script_copyright("This script is Copyright (C) 2003 Michel Arboi");
 family = "SMTP problems";
 script_family(family);

 script_dependencies("smtpserver_detect.nasl", "smtp_settings.nasl", "smtp_relay.nasl");
 script_require_ports("Services/smtp", 25);
 script_exclude_keys("SMTP/spam", "SMTP/wrapped");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# The script code starts here

include("smtp_func.inc");

# Disable the test if the server relays e-mails.
if (get_kb_item("SMTP/spam")) exit(0);

fromaddr = smtp_from_header();
toaddr = smtp_to_header();

port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);

if(!get_port_state(port))exit(0);

b = string("From: ", fromaddr, "\r\n", "To: ", toaddr, "\r\n",	
	"Subject: OpenVAS test - ignore it\r\n\r\n",
	crap(10000), "\r\n");
n = smtp_send_port(port: port, from: fromaddr, to: toaddr, body: b);
if (n > 0) security_note(port);
