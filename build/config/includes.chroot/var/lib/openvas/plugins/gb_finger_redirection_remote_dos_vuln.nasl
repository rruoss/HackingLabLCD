###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_finger_redirection_remote_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Finger Redirection Remote Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let the attacker to use this computer as a relay
  to gather information on a third-party network or cause a denial of service.
  Impact Level: Application";
tag_affected = "GNU Finger.";
tag_insight = "The flaw exists due to finger daemon allows redirecting a finger request to
  remote sites using the form finger 'username@hostname1@hostname2'.";
tag_solution = "Upgrade to GNU finger 1.37 or later,
  For updates refer, ftp://prep.ai.mit.edu/old-gnu/finger/finger-1.37.tar.gz";
tag_summary = "This host is running Finger service and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(802231);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_cve_id("CVE-1999-0106");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Finger Redirection Remote Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/64");
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/5769");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/47");
  script_xref(name : "URL" , value : "http://www.securityspace.com/smysecure/catid.html?id=10073");
  script_xref(name : "URL" , value : "http://www.iss.net/security_center/reference/vuln/finger-bomb.htm");

  script_description(desc);
  script_summary("Determine if Finger is prone to denial of service vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Finger abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/finger", 79);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


## Get Finger Port
port = get_kb_item("Services/finger");
if(!port){
  port = 79;
}

## Check Port Status
if(! get_port_state(port)){
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(port);
if(! soc){
  exit(0);
}

## Confirm Finger
banner = recv(socket:soc, length:2048, timeout:5);
if(banner) {
  exit(0);
}

## Send And Receive The Response
send(socket: soc, data: string("root@", get_host_name(), "\r\n"));
res = recv(socket:soc, length:65535);
close(soc);

## Confirm Vulnerability
res = tolower(res);
if( res && "such user" >!< res && "doesn't exist" >!< res &&
    "???" >!< res && "invalid" >!< res && "forward" >!< res){
  security_warning(port);
}
