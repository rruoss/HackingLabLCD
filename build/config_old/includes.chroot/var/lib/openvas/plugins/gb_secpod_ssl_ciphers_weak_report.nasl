###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_secpod_ssl_ciphers_weak_report.nasl 12 2013-10-27 11:15:33Z jan $
#
# Check for SSL Weak Ciphers
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This Plugin report about SSL Weak Ciphers.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103440";

if (description)
{

 script_oid(SCRIPT_OID);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-03-01 17:16:10 +0100 (Thu, 01 Mar 2012)");
 script_name("Check for SSL Weak Ciphers");
 desc = "
 Summary:
 " + tag_summary; script_description(desc);
 script_summary("Checks for the presence of SSL Weak Ciphers");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("secpod_ssl_ciphers.nasl");
 script_require_keys("secpod_ssl_ciphers/weak");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

SCRIPT_DESC = "Check for SSL Weak Ciphers";

port = get_kb_item("TCP/PORTS");

if(!get_kb_item(string("secpod_ssl_ciphers/", port, "/weak"))) exit(0);

report = get_kb_item(string("secpod_ssl_ciphers/",port,"/report"));

if(report) {
  security_warning(port:port,data:report);
}

exit(0);
