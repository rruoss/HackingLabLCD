###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_proftpd_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# ProFTPD Multiple Remote Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation may allow execution of arbitrary code or cause a
  denial-of-service.
  Impact Level: Application";
tag_affected = "ProFTPD versions prior to 1.3.3c";
tag_insight = "- An input validation error within the 'mod_site_misc' module can be exploited
    to create and delete directories, create symlinks, and change the time of
    files located outside a writable directory.
  - A logic error within the 'pr_netio_telnet_gets()' function in 'src/netio.c'
    when processing user input containing the Telnet IAC escape sequence can be
    exploited to cause a stack-based buffer overflow by sending specially
    crafted input to the FTP or FTPS service.";
tag_solution = "Upgrade to ProFTPD version 1.3.3c or later,
  For updates refer to http://www.proftpd.org/";
tag_summary = "The host is running ProFTPD and is prone to multiple vulnerabilities.";

if(description)
{
  script_id(801639);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_cve_id("CVE-2010-3867", "CVE-2010-4221");
  script_bugtraq_id(44562);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("ProFTPD Multiple Remote Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42052");
  script_xref(name : "URL" , value : "http://bugs.proftpd.org/show_bug.cgi?id=3519");
  script_xref(name : "URL" , value : "http://bugs.proftpd.org/show_bug.cgi?id=3521");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-229/");

  script_description(desc);
  script_summary("Check for the version of ProFTPD");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_proftpd_server_remote_detect.nasl");
  script_require_keys("Services/ftp", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

## Get FTP Port
port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(!get_port_state(port)){
  exit(0);
}

## Get Version from KB
version = get_kb_item("ProFTPD/Ver");
if(!isnull(version))
{
  ## Check for ProFTPD versions prior to 1.3.3c
  if(version_is_less(version:version,  test_version:"1.3.3.c")){
    security_hole(port);
  }
}
