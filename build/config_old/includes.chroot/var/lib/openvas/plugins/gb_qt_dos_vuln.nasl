###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qt_dos_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Qt 'QSslSocketBackendPrivate::transmit()' Denial of Service Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to cause a denial of service.
  Impact Level: Application";
tag_affected = "Qt Version 4.6.3 and prior.";
tag_insight = "This flaw is due to an endless loop within the 'QSslSocketBackendPrivate::transmit()'
  function in 'src/network/ssl/qsslsocket_openssl.cpp'. This can be exploited to
  exhaust CPU resources in server applications using the QSslSocket class.";
tag_solution = "No solution or patch is available as of 20th July, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://qt.nokia.com/downloads";
tag_summary = "This host is installed with Qt and is prone to denial of service
  vulnerability.";

if(description)
{
  script_id(801235);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_bugtraq_id(41250);
  script_cve_id("CVE-2010-2621");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Qt 'QSslSocketBackendPrivate::transmit()' Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40389");
  script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/qtsslame-adv.txt");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1657");

  script_description(desc);
  script_summary("Check for the version of Qt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_qt_detect.nasl");
  script_require_keys("Qt/Ver");
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

## Get version from KB
ver = get_kb_item("Qt/Ver");

if(ver != NULL)
{
  ##Grep for Qt version 4.6.3 and prior
  if(version_is_less_equal(version:ver, test_version:"4.6.3") ){
    security_warning(0);
  }
}
