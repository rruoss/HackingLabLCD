###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_calendar_rfi_n_lfi_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# PHP-Calendar Multiple Remote And Local File Inclusion Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to include and execute arbitrary
  files from local and external resources, and can gain sensitive information
  about remote system directories when register_globals is enabled.

  Impact level: Application";

tag_affected = "PHP-Calendar version 1.1 and prior on all platforms.";
tag_insight = "The flaw is due to error in 'configfile' parameter in 'update08.php' and
  'update10.php' which  is not properly verified before being used to include
  files.";
tag_solution = "Upgrade to PHP-Calendar version 1.4 or later,
  For updates refer to http://www.cascade.org.uk/software/php/calendar/";
tag_summary = "This host is running PHP Calendar and is prone to Remote And Local
  File Inclusion vulnerability.";

if(description)
{
  script_id(901090);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-31 08:44:14 +0100 (Thu, 31 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-3702");
  script_bugtraq_id(37450);
  script_name("PHP-Calendar Multiple Remote And Local File Inclusion Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/508548/100/0/threaded");

  script_description(desc);
  script_summary("Check PHP Calendar version");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_php_calendar_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

calPort = get_http_port(default:80);
if(!calPort){
  exit(0);
}

calVer = get_kb_item("www/" + calPort + "/PHP-Calendar");
calVer = eregmatch(pattern:"^(.+) under (/.*)$", string:calVer);

if((calVer[2] != NULL) && (!safe_checks()))
{
  sndReq = http_get(item:string(calVer[2], "/update08.php?configfile=" +
                                           "/etc/passwd"), port:calPort);
  rcvRes = http_send_recv(port:calPort, data:sndReq);
  if("Your SQL password is:" >< rcvRes)
  {
    security_hole(calPort);
    exit(0);
  }

  sndReq = http_get(item:string(calVer[2], "/update10.php?configfile=" +
                                           "/etc/passwd"), port:calPort);
  rcvRes = http_send_recv(port:calPort, data:sndReq);
  if("Your SQL username is:" >< rcvRes)
  {
    security_hole(calPort);
    exit(0);
  }
}

if(calVer[1] != NULL)
{
  if(version_is_less_equal(version:calVer[1], test_version:"1.1")){
    security_hole(calPort);
  }
}
