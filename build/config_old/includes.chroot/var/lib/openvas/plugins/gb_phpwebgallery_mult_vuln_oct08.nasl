###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpwebgallery_mult_vuln_oct08.nasl 16 2013-10-27 13:09:52Z jan $
#
# Multiple XSS Vulnerabilities in PHPWebGallery - Oct08
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
tag_impact = "Successful attack could lead to execution of arbitrary HTML or scripting
  code in the security context of an affected web page.
  Impact Level: Application";
tag_affected = "PHPWebGallery Version 1.3.4 and prior on all running platform.";
tag_insight = "The flaws are due to improper validation of input data to parameters
  in isadmin.inc.php and init.inc.php file, which allow remote attackers to
  inject arbitrary web script via lang[access_forbiden], lang[ident_title],
  user[language] and user[template] parameters.";
tag_solution = "No solution or patch is available as of 21st October, 2008. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://download.gna.org/phpwebgallery/";
tag_summary = "The host is running PHPWebGallery which is prone to multiple
  XSS and script inclusion Vulnerabilities.";

if(description)
{
  script_id(800115);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-21 16:25:40 +0200 (Tue, 21 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-4591", "CVE-2008-4702");
  script_name("Multiple XSS Vulnerabilities in PHPWebGallery - Oct08");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/6425");

  script_description(desc);
  script_summary("Check for the Version of PHPWebGallery");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
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
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!port){
  exit(0);
}

dirs = make_list("/phpwebgallery", cgi_dirs());
foreach dir (dirs)
{
  url = dir + "/category.php";
  sndReq = http_get(item:url, port:port);
  rcvRes = http_keepalive_send_recv(port:port,data:sndReq,bodyonly:1);

  if(rcvRes == NULL){
    exit(0);
  }

  if(rcvRes =~ "Powered by.+PhpWebGallery")
  {
    if(safe_checks())
    {
      rcvRes = eregmatch(pattern:"PhpWebGallery.+ ([0-9.]+)", string:rcvRes);
      if(rcvRes != NULL)
      {
        if(version_is_less_equal(version:rcvRes[1], test_version:"1.3.4")){
          security_hole(port);
        }
      }
      exit(0);
    }
    url = dir + "/admin/include/isadmin.inc.php?lang[access_forbiden]="+
                "<script>alert(document.cookie);</script>";
    sndReq = http_get(item:url, port:port);
    rcvRes = http_keepalive_send_recv(port:port,data:sndReq,bodyonly:1);
    if(rcvRes == NULL){
      exit(0);
    }

    if("<script>alert(document.cookie);</script>" >< rcvRes){
      security_hole(port);
    }
    exit(0);
  }
}
