###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ssl_ciphers_setting.nasl 50 2013-11-07 18:27:30Z jan $
#
# SSL Cipher Settings
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_summary = "This plugin Set SSL Cipher Settings.

  This plugin will gets the ssl cipher settings from user preference and
  sets into the KB.";


if(description)
{
  script_id(900238);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 50 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-07 19:27:30 +0100 (Do, 07. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-04-16 11:02:50 +0200 (Fri, 16 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("SSL Cipher Settings");
  desc = "

  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Get SSL Cipher Settings");
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Settings");

  script_add_preference(name:"List SSL Supported Ciphers", type:"checkbox", value:"no");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

## Get SSL Supported Ciphers user preference
ssl_supported_ciphers_enabled = script_get_preference("List SSL Supported Ciphers");

if(ssl_supported_ciphers_enabled){
  ## iSet SSL Supported Ciphers into the KB
  set_kb_item(name: "SSL/SupportedCiphers/Enabled", value: ssl_supported_ciphers_enabled);
}
