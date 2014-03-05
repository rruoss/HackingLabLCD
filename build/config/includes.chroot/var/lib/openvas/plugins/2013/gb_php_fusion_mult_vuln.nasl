###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_fusion_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# PHP-Fusion Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site and manipulate SQL queries by injecting arbitrary SQL code or disclose
  or manipulation of arbitrary data.
  Impact Level: Application";

tag_affected = "PHP-Fusion Version 7.02.05 and prior versions may also be affected";
tag_insight = "Multiple Flaws exist in PHP-Fusion,
  For more details about the vulnerabilities refer the reference section.";
tag_solution = "Upgrade to PHP-Fusion Version 7.02.06 or later,
  For updates refer to http://www.php-fusion.co.uk/downloads.php";
tag_summary = "This host is installed with PHP-Fusion and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803431);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1803", "CVE-2013-1804", "CVE-2013-1805", "CVE-2013-1806",
                "CVE-2013-1807");
  script_bugtraq_id(58226, 58265, 58270);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-07 13:36:54 +0530 (Thu, 07 Mar 2013)");
  script_name("PHP-Fusion Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/52403");
  script_xref(name : "URL" , value : "http://secunia.com/52226");
  script_xref(name : "URL" , value : "http://www.osvdb.com/90697");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Feb/149");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24562");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120598/PHP-Fusion-7.02.05-XSS-LFI-SQL-Injection.html");

  script_description(desc);
  script_summary("Check if PHP-Fusion is vulnerable to sql injection");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_dependencies("secpod_php_fusion_detect.nasl");
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
include("http_keepalive.inc");

## Variable Initialization
port = "";
req = "";
res = "";
url = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over the possible directories
foreach dir (make_list("", "/php-fusion", "/phpfusion", cgi_dirs()))
{
  ## Iterate over the  possible subdirectories
  foreach subdir (make_list("", "/files", "/php-files"))
  {
    ## Request for the news.php
    sndReq = http_get(item:string(dir + subdir, "/news.php"), port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    ## confirm the PHP-Fusion installation
    if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes) &&
                     ("PHP-Fusion Powered" >< rcvRes))
    {
      ## Construct Attack Request
      url = dir + subdir + "/downloads.php?cat_id=1&orderby='SQL-Injection-Test";

      ## Try attack and check the response to confirm vulnerability
      if(http_vuln_check(port:port, url:url, check_header:TRUE,
            pattern:"You have an error in your SQL syntax.*SQL-Injection-Test"))
      {
        security_hole(port);
        exit(0);
      }
    }
  }
}
