##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpvidz_info_disc_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# PHPvidz Administrative Credentials Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to obtain sensitive
  information.
  Impact Level: Application.";
tag_affected = "PHPvidz version 0.9.5";

tag_insight = "phpvidz uses a system of flat files to maintain application state.
  The administrative password is stored within the '.inc' file and
  is included during runtime.";
tag_solution = "No solution or patch is available as of 25th November, 2010. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/phpvidz/";
tag_summary = "This host is running PHPvidz and is prone to administrative
  credentials disclosure vulnerability.";

if(description)
{
  script_id(801549);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PHPvidz Administrative Credentials Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2010/May/129");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15606/");
  script_xref(name : "URL" , value : "http://www.mail-archive.com/bugtraq@securityfocus.com/msg33846.html");

  script_description(desc);
  script_summary("Check information disclosure vulnerability in PHPvidz");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

pcmsPort = get_http_port(default:80);
if(!pcmsPort){
  exit(0);
}

foreach dir (make_list("/phpvidz_0.9.5","/phpvidz"))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:pcmsPort);
  rcvRes = http_send_recv(port:pcmsPort, data:sndReq);

  ## Confirm the application
  if(">PHPvidz<" >< rcvRes)
  {
    ## Try attack and check the response to confirm vulnerability.
    if(http_vuln_check(port:pcmsPort, url:dir + "/includes/init.inc",
                       pattern:"(define .'ADMINPASSWORD)"))
    {
      security_hole(port:pcmsPort);
      exit(0);
    }
  }
}
