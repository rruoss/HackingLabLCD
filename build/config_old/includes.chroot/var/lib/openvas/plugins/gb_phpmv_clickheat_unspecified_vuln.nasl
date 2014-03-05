###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmv_clickheat_unspecified_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# PhpMyVisites ClickHeat Plugin Unspecified Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Upgrade to the latest version of phpMyVisites 2.4 or later,
  For updates refer to http://www.phpmyvisites.us/downloads.html

  *****
  NOTE : Ignore this warning, if 'ClickHeat' Plugin is not installed or disabled.
  *****";

tag_impact = "Unknown impact and attack vectors.
  Impact Level: Application";
tag_affected = "PhpMyVisites 2.3 and prior";
tag_insight = "The flaw is due to an unspecified error related to the ClickHeat
  plugin used in phpMyVisites.";
tag_summary = "This host is running PhpMyVisites and is prone to unspecified
  vulnerabilities.";

if(description)
{
  script_id(801202);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-07 16:20:50 +0200 (Wed, 07 Apr 2010)");
  script_cve_id("CVE-2009-4763");
  script_bugtraq_id(38824);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PhpMyVisites ClickHeat Plugin Unspecified Vulnerability");
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

  script_xref(name : "URL" , value : "http://www.phpmyvisites.us/phpmv2/CHANGELOG");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57004");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38824");

  script_description(desc);
  script_summary("Check for the version of PhpMyVisites");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
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
include("http_keepalive.inc");
include("version_func.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/", "/phpmv2", "/phpmyvisites", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if('>phpMyVisites' >< res)
  {
    ## Get PhpMyVisites Version
    ver = eregmatch(pattern:'"version" content="([0-9\\.]+)"', string:res);

    if(ver[1])
    {
      ## Check for version before 2.4
      if(version_is_less(version:ver[1], test_version:"2.4"))
      {
        security_hole(port);
        exit(0);
      }
    }
  }
}
