###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_postfix_cyrus_sasl_memory_corruption_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Postfix SMTP Server Cyrus SASL Support Memory Corruption Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to cause a denial of
  service or possibly execute arbitrary code.
  Impact Level: Application";
tag_affected = "Postfix versions before 2.5.13, 2.6.x before 2.6.10, 2.7.x before 2.7.4,
  and 2.8.x before 2.8.3";
tag_insight = "The flaw is caused by a memory corruption error in the Cyrus SASL library
  when used with 'CRAM-MD5' or 'DIGEST-MD5' authentication mechanisms, which
  could allow remote attackers to crash an affected server or execute arbitrary
  code.";
tag_solution = "Upgrade to Postfix version 2.5.13, 2.6.10, 2.7.4, or 2.8.3 or later
  For updates refer to http://www.postfix.org/";
tag_summary = "This host is running Postfix SMTP server and is prone to memory
  corruption vulnerability.";

if(description)
{
  script_id(902517);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)");
  script_cve_id("CVE-2011-1720");
  script_bugtraq_id(47778);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Postfix SMTP Server Cyrus SASL Support Memory Corruption Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44500");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/727230");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/67359");
  script_xref(name : "URL" , value : "http://www.postfix.org/CVE-2011-1720.html");

  script_description(desc);
  script_summary("Check if Postfix is vulnerable to Memory Corruption");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("SMTP problems");
  script_dependencies("find_service.nasl","smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smtp_func.inc");
include("version_func.inc");

## Variable Initialization
soc = 0;
port = 0;
banner = "";
version = "";

## This nvt is prone to FP
if(report_paranoia < 2){
  exit(0);
}

## Get SMTP Port
port = get_kb_item("Services/smtp");
if(!port) {
  port = 25;
}

if(get_kb_item('SMTP/'+port+'/broken')) {
  exit(0);
}

if(!get_port_state(port)) {
  exit(0);
}

## Confirm Postfix
banner = get_smtp_banner(port:port);
if("ESMTP Postfix" >!< banner) {
  exit(0);
}

## Get version from banner
version = eregmatch(pattern:"220.*Postfix \(([0-9\.]+)\)", string:banner);
if(! version[1]){
  exit(0);
}

## Check for vulnerable versions
if(version_is_less(version:version[1], test_version:"2.5.13") ||
   version_in_range(version:version[1], test_version:"2.6", test_version2:"2.6.9")||
   version_in_range(version:version[1], test_version:"2.7", test_version2:"2.7.3")||
   version_in_range(version:version[1], test_version:"2.8", test_version2:"2.8.2"))
{
  ## Open SMTP Socket
  if(!soc = smtp_open(port:port)) {
    exit(0);
  }

  ## Send EHLO Command
  send(socket:soc, data:string("EHLO ", get_host_name(), "\r\n"));
  if(!resp = smtp_recv_line(socket:soc)) {
    exit(0);
  }

  smtp_close(socket:soc);

  ## Check for vulnerable authentication methods.
  if("DIGEST-MD5" >< resp || "CRAM-MD5" >< resp) {
    security_hole(port:port);
  }
}
