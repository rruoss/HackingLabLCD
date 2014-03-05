###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gallery_sec_bypass_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# Gallery Unspecified Security Bypass Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation allows attackers to bypass authentication and gain
  administrative access to the application, if register_globals is enabled.
  Impact Level: Application";
tag_affected = "Gallery Version 1.5.x before 1.5.10 and 1.6 before 1.6-RC3 on all
  platform.";
tag_insight = "The flaw is due to improper validation of authentication cookies.";
tag_solution = "Update to version 1.5.10 or 1.6-RC3.
  http://codex.gallery2.org/Downloads";
tag_summary = "The host is running Gallery and is prone to Security Bypass
  Vulnerability.";

if(description)
{
  script_id(800312);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-05 15:00:57 +0100 (Fri, 05 Dec 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-5296");
  script_bugtraq_id(32440);
  script_name("Gallery Unspecified Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32817");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/46804");
  script_xref(name : "URL" , value : "http://gallery.menalto.com/last_official_G1_releases");

  script_description(desc);
  script_summary("Check for the Version of Gallery");
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

foreach dir (make_list("/gallery", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port,data:sndReq,bodyonly:1);
  if(rcvRes == NULL){
    exit(0);
  }

  if("Powered by Gallery" >< rcvRes)
  {
    gallVer = eregmatch(pattern:"([0-9.]+)(-[A-Z0-9]+)? -", string:rcvRes);
    gallVer = ereg_replace(pattern:" -", string:gallVer[0], replace:"");
    gallVer = ereg_replace(pattern:"-", string:gallVer, replace:".");

    if(gallVer != NULL)
    {
      # Grep version prior to 1.5.10 and 1.6-RC3
      if(gallVer =~ "^1.5" && version_in_range(version:gallVer,
                                  test_version:"1.5", test_version2:"1.5.9")){
        security_hole(port);
        exit(0);
      }
      if(gallVer =~ "^1.6" && version_in_range(version:gallVer,
                                test_version:"1.6", test_version2:"1.6.RC2")){
        security_hole(port);
        exit(0);
      }
    }
    exit(0);
  }
}
