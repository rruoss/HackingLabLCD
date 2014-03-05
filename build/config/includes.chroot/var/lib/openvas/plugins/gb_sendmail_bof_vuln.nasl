###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sendmail_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Sendmail Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will let the remote attacker to create the mangled
  message by execute arbitrary code, and can cause application crash.";
tag_affected = "Sendmail Version prior 8.13.2";
tag_insight = "Buffer overflow error is due to improper handling of long X- header.";
tag_solution = "Upgrade to version 8.13.2 or later
  http://www.sendmail.org/releases";
tag_summary = "The host is running Sendmail and is prone to Buffer Overflow Vulnerability.";

if(description)
{
  script_id(800609);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-1490");
  script_name("Sendmail Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.sendmail.org/releases/8.13.2");
  script_xref(name : "URL" , value : "http://www.nmrc.org/~thegnome/blog/apr09");

  script_description(desc);
  script_summary("Check for the version of Sendmail");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_sendmail_detect.nasl");
  script_require_ports("Services/smtp", 25);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
}


include("version_func.inc");

sendmailPort = get_kb_item("Services/smtp");

if(!sendmailPort){
  exit(0);
}

sendmailVer = get_kb_item("SMTP/" + sendmailPort + "/Sendmail");

if(sendmailVer != NULL)
{
  if(version_is_less(version:sendmailVer, test_version:"8.13.2")){
    security_warning(sendmailPort);
  }
}
