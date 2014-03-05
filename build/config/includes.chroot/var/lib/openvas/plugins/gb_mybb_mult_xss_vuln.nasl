###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mybb_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# MyBB Multiple Sross-Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to inject arbitrary web script
  or HTML.
  Impact Level: Application";
tag_affected = "MyBB 1.6 and prior.";
tag_insight = "The flaws are caused by improper validation of user-supplied input via
  vectors related to 'editpost.php', 'member.php', and 'newreply.php'.";
tag_solution = "Upgrade to MyBB version 1.6.1 or later,
  For updates refer to http://www.mybb.com/downloads";
tag_summary = "The host is running MyBB and is prone to multiple cross-site
  scripting vulnerabilities.";

if(description)
{
  script_id(801684);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-08 10:30:18 +0100 (Sat, 08 Jan 2011)");
  script_cve_id("CVE-2010-4522");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("MyBB Multiple Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2010/12/22/2");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2010/12/20/1");
  script_xref(name : "URL" , value : "http://blog.mybb.com/2010/12/15/mybb-1-6-1-release-1-4-14-update/");
  script_xref(name : "URL" , value : "http://yehg.net/lab/pr0js/advisories/[mybb1.6]_cross_site_scripting");

  script_description(desc);
  script_summary("Determine if MyBB is prone to cross-site scripting vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir(make_list("/mybb/", "/forum/", "/forums/", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get (item: string(dir, "index.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if(egrep(pattern:"Powered By .+>MyBB<", string:res))
  {
    ## Construct the Attack Request
    url = string(dir, "member.php?action=login&url=javascript:alert%28/XSS/%29");

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, pattern:"javascript:alert\(/XSS/\)",
                       check_header: TRUE))
    {
      security_warning(port);
      exit(0);
    }
  }
}
