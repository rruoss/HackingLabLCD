###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_request_array_csrf_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# WordPress _REQUEST array Cross Site Request Forgery (CSRF) Vulnerabilities.
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
tag_solution = "Upgrade to WordPress version 2.9.2 or later
  For updates refer to  http://wordpress.org/

  NOTE: This issue relies on the presence of an independent vulnerability that
  allows cookie injection.";

tag_impact = "Successful attack could lead to execution of arbitrary script code
  and can cause denial of service condition.
  Impact Level: Application";
tag_affected = "WordPress 2.6.3 and earlier on all running platforms.";
tag_insight = "The flaw is due to incorrect usage of _REQUEST super global array,
  which leads to cross site request forgery (CSRF) attacks via crafted cookies.";
tag_summary = "The host is installed with WordPress and is prone to Cross Site
  Request Forgery(CSRF) Vulnerabilities.";

if(description)
{
  script_id(800140);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5113");
  script_name("WordPress _REQUEST array Cross Site Request Forgery (CSRF) Vulnerability");
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

  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2008/11/14/1");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=504771");

  script_description(desc);
  script_summary("Check for the Version of WordPress");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
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

foreach dir (make_list("/wordpress", cgi_dirs()))
{
  sndReq = http_get(item:dir + "/index.php", port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);
  if(rcvRes == NULL){
    exit(0);
  }

  if(egrep(pattern:"Powered by WordPress", string:rcvRes) &&
     egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
  {
    wdPressVer = eregmatch(pattern:"WordPress ([0-9.]+)", string:rcvRes);
    if(wdPressVer[1] != NULL)
    {
      if(version_is_less_equal(version:wdPressVer[1], test_version:"2.6.3")){
        security_warning(port);
      }
    }
    exit(0);
  }
}
