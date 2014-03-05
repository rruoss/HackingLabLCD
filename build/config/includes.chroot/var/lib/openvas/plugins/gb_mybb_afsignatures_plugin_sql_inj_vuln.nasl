##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mybb_afsignatures_plugin_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# MyBB Advanced Forum Signatures (afsignatures) Plugin 'signature.php' SQL Injection Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code and gain sensitive information.
  Impact Level: Application";
tag_affected = "MyBB Advanced Forum Signatures (afsignatures) Plugin Version 2.0.4, Other
  versions may also be affected.";
tag_insight = "The flaw is due to input passed via multiple parameters to
  'signature.php', which is not properly sanitised before being
  used in a SQL query.";
tag_solution = "No solution or patch is available as of 11th October 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://mods.mybb.com/view/advanced-forum-signatures";
tag_summary = "This host is running MyBB with Advanced Forum Signatures
  (afsignatures) Plugin and is prone to SQL injection vulnerability.";

if(description)
{
  script_id(802039);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("MyBB Advanced Forum Signatures (afsignatures) Plugin 'signature.php' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17961");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/105661");
  script_xref(name : "URL" , value : "http://mods.mybb.com/view/advanced-forum-signatures");

  script_description(desc);
  script_summary("Check if MyBB Advanced Forum Signatures (afsignatures) Plugin is vulnerable for SQL Injection attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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

##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("/forum", "/mybb", "", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:dir + "/index.php", port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application before trying exploit
  if(">MyBB<" >< res && ">MyBB Group<" >< res)
  {
    ## Path of Vulnerable Page
    path2 = dir + "/signature.php";

    ## Post Data having attack data
    postData = "afs_bar_right=postcount''SQLi;--";

    ## Construct POST Attack Request
    req = http_post(item:path2, port:port, data:postData);

    ## Send crafted request and receive the response
    res = http_send_recv(port:port, data:req);

    ## Confirm exploit worked by checking the response
    if("MyBB has experienced an internal SQL error and cannot " +
       "continue." >< res && "You have an error in your SQL syntax" >< res)
    {
      security_hole(port);
      exit(0);
    }
  }
}