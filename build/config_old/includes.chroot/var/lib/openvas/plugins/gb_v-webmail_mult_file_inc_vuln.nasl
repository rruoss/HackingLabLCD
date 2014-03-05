###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_v-webmail_mult_file_inc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# V-webmail Multiple PHP Remote File Inclusion Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let the remote attacker to execute arbitrary
  PHP code via a URL in the CONFIG[pear_dir] or CONFIG[includes] parameters
  when register_globals is enabled.
  Impact Level: Application";
tag_affected = "V-webmail version 1.6.4 and prior";
tag_insight = "The flaws are due to error in 'CONFIG[pear_dir]' parameter to Mail/RFC822.php,
  Net/Socket.php, XML/Parser.php, XML/Tree.php, Mail/mimeDecode.php, Log.php,
  Console/Getopt.php, System.php, and File.php in includes/pear/ directory and
  also in includes/cachedConfig.php, includes/mailaccess/pop3.php, and
  includes/prepend.php files, and error exists in 'CONFIG[includes]' parameter
  to prepend.php and email.list.search.php in includes/.";
tag_solution = "No solution or patch is available as of 02nd July, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/v-webmail/";
tag_summary = "The host is running V-webmail and is prone to Multiple PHP Remote File
  Inclusion vulnerability.";

if(description)
{
  script_id(800822);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-6840", "CVE-2006-2666");
  script_bugtraq_id(30162, 30164);
  script_name("V-webmail Multiple PHP Remote File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/1827");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/20297");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/0807-exploits/vwebmail-rfi.txt");

  script_description(desc);
  script_summary("Check for the Attack and Version of V-webmail");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_v-webmail_detect.nasl");
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

vwmailPort = get_http_port(default:80);
if(!vwmailPort){
  exit(0);
}

vwmailVer = get_kb_item("www/" + vwmailPort + "/V-webmail");
vwmailVer = eregmatch(pattern:"^(.+) under (/.*)$", string:vwmailVer);

if(vwmailVer[2] != NULL && (!safe_checks()))
{
  sndReq = http_get(item:vwmailVer[2] + "/includes/mailaccess/pop3.php" +
                                        "?CONFIG[pear_dir]=[SHELL]",
                    port:vwmailPort);
  rcvRes = http_send_recv(data:sndReq, port:vwmailPort);
  if("SHELL" >!< rcvRes)
  {
    sndReq = http_get(item:vwmailVer[2] + "/includes/prepend.php?" +
                                          "CONFIG[includes]=[SHELL]",
                      port:vwmailPort);
    rcvRes = http_send_recv(data:sndReq, port:vwmailPort);
  }
  if("SHELL" >< rcvRes && egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
  {
    security_hole(vwmailPort);
    exit(0);
  }
}

if(vwmailVer[1] != NULL)
{
  if(version_is_less_equal(version:vwmailVer[1], test_version:"1.6.4"))
  {
    security_hole(vwmailPort);
    exit(0);
  }
}
