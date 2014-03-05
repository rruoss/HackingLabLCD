###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ssl_ciphers_medium_report.nasl 12 2013-10-27 11:15:33Z jan $
#
# Check for SSL Medium Ciphers
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_summary = "This Plugin reports about SSL Medium Ciphers.";

if (description)
{
  script_id(902816);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-07 14:14:14 +0530 (Wed, 07 Mar 2012)");
  script_name("Check for SSL Medium Ciphers");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Checks for the presence of SSL Medium Ciphers");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2012 SecPod");
  script_dependencies("secpod_ssl_ciphers.nasl");
  script_require_keys("secpod_ssl_ciphers/medium");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


port = 0;
report = "";

## Get all tcp ports
port = get_kb_item("TCP/PORTS");
if(! port){
  exit(0);
}

## Get the Medium Ciphers
report = get_kb_item(string("secpod_ssl_ciphers/",port,"/medium_ciphers"));
if(report) {
  log_message(port:port, data:report);
}
