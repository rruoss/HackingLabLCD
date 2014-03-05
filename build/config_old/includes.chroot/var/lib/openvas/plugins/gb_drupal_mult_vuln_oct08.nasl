###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_mult_vuln_oct08.nasl 16 2013-10-27 13:09:52Z jan $
#
# Drupal Core Multiple Vulnerabilities
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation allows authenticated users to bypass
  access restrictions and can even allows unauthorized users to obtain
  sensitive information.
  Impact Level: Application";
tag_affected = "Drupal Version 5.x prior to 5.11 and 6.x prior to 6.5 on all running platform.";
tag_solution = "Upgrade Drupal Version 5.x to 5.11/6.x to Drupal 6.5 or later.
  http://drupal.org/";

desc = "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://drupal.org/node/318706");
  script_id(800123);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-04 15:12:12 +0100 (Tue, 04 Nov 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-4789", "CVE-2008-4790" ,
                "CVE-2008-4791", "CVE-2008-4793");
  script_name("Drupal Core Multiple Vulnerabilities");
  script_description(desc);
  script_summary("Check for the Version of Drupal");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

report = string("\n  Overview: This host is installed with Drupal and is prone to\n" +
                "  Multiple Vulnerabilities.\n" +
                "\n  Vulnerability Insight:" +
                "\n  Flaws are due to,\n");
vuln1 = string("  - logic error in the core upload module validation, which allows\n" +
               "    unprivileged users to attach files.\n");
vuln2 = string("  - ability to view attached file content which they don't have access.\n");
vuln3 = string("  - deficiency in the user module allows users who had been blocked\n" +
               "    by access rules.\n");
vuln4 = string("  - weakness in the node module API allows for node validation to\n" +
               "    be bypassed in certain circumstances.\n");

port = get_http_port(default:80);
if(!port){
  exit(0);
}

dirs = make_list("/drupal", cgi_dirs());
foreach dir (dirs)
{
  url = dir + "/CHANGELOG.txt";
  sndReq = http_get(item:url, port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:1);
  if(rcvRes == NULL){
    exit(0);
  }

  if(rcvRes  =~ "Drupal")
  {
    drupalVer = eregmatch(pattern:"Drupal ([0-9.]+)", string:rcvRes);
    if(drupalVer[1] =~ "^6.*")
    {
      if(version_is_less(version:drupalVer[1], test_version:"6.5")){
        security_hole(data:string(report, vuln1, vuln3, desc));
        exit(0);
      }
    }
    else if(drupalVer[1] =~ "^5.*")
    {
      if(version_is_less(version:drupalVer[1], test_version:"5.11")){
        security_hole(data:string(report, vuln2, vuln3, vuln4, desc));
        exit(0);
      }
    }
    exit(0);
  }
}
