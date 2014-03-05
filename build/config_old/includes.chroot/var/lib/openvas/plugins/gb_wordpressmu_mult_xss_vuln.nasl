###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpressmu_mult_xss_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# WordPress MU Multiple XSS Vulnerabilities - Oct08
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
tag_impact = "Successful attack could lead to execution of arbitrary HTML and
  script code in the context of an affected site and attackers can steal
  cookie-based authentication credentials.
  Impact Level: Application";
tag_affected = "WordPress MU before 2.6 on all running platform.";
tag_insight = "The flaws are due to the 's' and 'ip_address' parameters in
  wp-admin/wp-blogs.php which is not properly sanitized before being returned
  to the user.";
tag_solution = "Update to Version 2.6 or later.
  http://wordpress.org/";
tag_summary = "The host is running WordPress MU, which is prone to Multiple
  XSS Vulnerabilities.";

if(description)
{
  script_id(800125);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-05 06:52:23 +0100 (Wed, 05 Nov 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-4671");
  script_bugtraq_id(31482);
  script_name("WordPress MU Multiple XSS Vulnerabilities - Oct08");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32060");
  script_xref(name : "URL" , value : "http://www.juniper.fi/security/auto/vulnerabilities/vuln28845.html");

  script_description(desc);
  script_summary("Check for the Version of WordPress MU");
  script_category(ACT_GATHER_INFO);
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

dirs = make_list("/wordpress-mu", cgi_dirs());
foreach dir (dirs)
{
  url = dir + "/index.php";
  sndReq = http_get(item:url, port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);
  if(rcvRes == NULL){
    exit(0);
  }

  if(egrep(pattern:"WordPress Mu", string:rcvRes) &&
     egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
  {
    wdPressVer = eregmatch(pattern:"WordPress ([0-9.]+)", string:rcvRes);
    if(wdPressVer != NULL)
    {
      if(version_is_less(version:wdPressVer[1], test_version:"2.6")){
        security_warning(port);
      }
    }
    exit(0);
  }
}
