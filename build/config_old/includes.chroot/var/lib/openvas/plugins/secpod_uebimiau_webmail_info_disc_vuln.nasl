###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_uebimiau_webmail_info_disc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Uebimiau Webmail Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to gain sensitive information
  in the context of the affected web application.
  Impact Level: Application";
tag_affected = "Uebimiau Webmail version 3.2.0-2.0";
tag_insight = "Error is due to an improper sanitization of user supplied input in
  the 'system_admin/admin.ucf' file.";
tag_solution = "No solution or patch is available as of 18th September, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.uebimiau.org/download.php";
tag_summary = "This host is running Uebimiau Webmail and is prone to Information
  Disclosure Vulnerability.";

if(description)
{
  script_id(901024);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-22 10:03:41 +0200 (Tue, 22 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3199");
  script_name("Uebimiau Webmail Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9493");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/52724");

  script_description(desc);
  script_summary("Check for the version of Uebimiau Webmail");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_uebimiau_webmail_detect.nasl");
  script_require_ports("Services/www", 80);
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

uwebPort = get_http_port(default:80);
if(!uwebPort){
  exit(0);
}

uwebVer = get_kb_item("www/" + uwebPort + "/Uebimiau/Webmail");
if(!uwebVer){
  exit(0);
}

uwebVer = eregmatch(pattern:"^(.+) under (/.*)$", string:uwebVer);

if((!safe_checks()) && (uwebVer[2] != NULL))
{
  request = http_get(item:string(uwebVer[2] + "/inc/database/system_admin"+
                                             "/admin.ucf"), port:uwebPort);
  response = http_send_recv(port:uwebPort, data:request);

  if(eregmatch(pattern:":[a-z0-9]{32,32}", string:response) &&
     egrep(pattern:"^HTTP/.* 200 OK", string:response))
  {
    security_warning(uwebPort);
    exit(0);
  }
}

if(uwebVer[1] != NULL)
{
  if(version_is_equal(version:uwebVer[1], test_version:"3.2.0.2.0")){
    security_warning(uwebPort);
  }
}