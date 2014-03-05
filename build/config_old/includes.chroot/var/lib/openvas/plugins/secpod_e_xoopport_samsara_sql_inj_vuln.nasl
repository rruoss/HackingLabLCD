###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_e_xoopport_samsara_sql_inj_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# E-Xoopport - Samsara SQL Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to cause SQL Injection attack
  and gain sensitive information.
  Impact Level: Application";
tag_affected = "E-Xoopport Samsara Version 3.1 and prior.";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'secid' parameter to modules/sections/index.php that allows attacker to
  manipulate SQL queries by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 27th September, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/exoopport/";
tag_summary = "The host is running E-Xoopport - Samsara and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_id(901159);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_cve_id("CVE-2010-3467");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("E-Xoopport - Samsara SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41397");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/61808");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15004");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1009-exploits/exoopport-sql.txt");

  script_description(desc);
  script_summary("Check for the version of E-Xoopport");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/Samsara", "/", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/modules/news/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application and Get Version
  samVer = eregmatch(pattern:'>Powered by E-Xoopport ([0-9.]+)', string:res);

  if(samVer[1] != NULL)
  {
    ## Check for E-Xoopport Samsara Version <= 3.1
    if(version_is_less_equal(version:samVer[1], test_version:"3.1"))
    {
      security_hole(port);
      exit(0);
    }
  }
}
