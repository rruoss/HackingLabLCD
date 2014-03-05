###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Check if Port 443 on an Apache Server, SSL enabled
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script checks if SSL on Port 443 on an Apache Server enabled.";

if(description)
{
  script_id(96034);
  script_version("$Revision: 9 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 10:38:41 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Check SSL on Apache");

  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Check if Port 443 on an Apache Server, SSL enabled");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("misc_func.inc");

soc = http_open_socket(443);
if (! soc)
{
 log_message(port:0, proto: "IT-Grundschutz", data:string("No access to Port 443."));
 set_kb_item(name:"GSHB/APACHE/SSL", value:"inapplicable");
 exit(0);
}
send(socket: soc, data: 'GET / HTTP/1.0\r\n\r\n');
banner = recv(socket: soc, length: 65535);
http_close_socket(soc);
if (! banner)
{
 log_message(port:0, proto: "IT-Grundschutz", data:string("No Banner received through Port 443"));
 set_kb_item(name:"GSHB/APACHE/SSL", value:"error");
 set_kb_item(name:"GSHB/APACHE/SSL/log", value:"IT-Grundschutz: No Banner received through Port 443");
 exit(0);
}

if (egrep(pattern:"Server: Apache", string:banner))
{
  set_kb_item(name:"GSHB/APACHE/SSL", value:"false");
  exit(0);
}
else if (egrep(pattern:"Reason: You're speaking plain HTTP to an SSL-enabled server port.", string:banner))
{
  set_kb_item(name:"GSHB/APACHE/SSL", value:"true");
  exit(0);
}
else set_kb_item(name:"GSHB/APACHE/SSL", value:"inapplicable");
exit(0);









