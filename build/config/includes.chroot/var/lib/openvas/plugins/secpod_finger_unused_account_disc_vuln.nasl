###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_finger_unused_account_disc_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Finger Service Unused Account Disclosure Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.
  Impact Level: Application";
tag_affected = "GNU Finger.";
tag_insight = "The flaw exists due to finger service display a list of unused accounts for
  a 'finger 0@host' request.";
tag_solution = "Disable finger service, or install a finger service or daemon that
  limits the type of information provided.";
tag_summary = "This host is running Finger service and is prone to information
  disclosure vulnerability.";

if(description)
{
  script_id(902555);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-1999-0197");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Finger Service Unused Account Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/60");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/8378");
  script_xref(name : "URL" , value : "http://www.iss.net/security_center/reference/vuln/finger-unused-accounts.htm");

  script_description(desc);
  script_summary("Determine if Finger is prone to information disclosure vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
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
send(socket: soc, data: string("0\r\n"));
res = recv(socket:soc, length:2048);
close(soc);

## Confirm Vulnerability
if(strlen(res) > 150)
{
  if("adm" >< res || "bin" >< res || "daemon" >< res ||
      "lp" >< res || "sys" >< res){
    security_hole(port);
  }
}
