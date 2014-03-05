# OpenVAS
# $Id: smb_authorization.nasl 42 2013-11-04 19:41:32Z jan $
# Description: Set information for smb authorization in KB.
#
# Authors:
# Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or, at your option, any later version as published by the
# Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

include("revisions-lib.inc");
tag_summary = "This script allows users to enter the information
required to authorize and login via SMB.

These data are stored in the knowledge base
and used by other tests.";

# The two entries "SMB/dont_send_ntlmv1" and "SMB/dont_send_in_cleartext"
# are not handled here yet. They are still managed in logins.nasl.

# Unlike the old code in logins.nasl, here only a single
# set of credentials in managed. Thus the strange name
# used for the KB.

if(description)
{
 script_id(90023);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 42 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2008-06-02 00:42:27 +0200 (Mon, 02 Jun 2008)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "SMB Authorization";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);

 summary = "Sets SMB authorization";
 script_summary(summary);

 script_category(ACT_SETTINGS);

 script_copyright("Copyright 2008 Greenbone Networks GmbH");
 family = "Credentials";
 script_family(family);

 script_add_preference(name:"SMB login:", type:"entry", value:"");
 script_add_preference(name:"SMB password:", type:"password", value:"");
 script_add_preference(name:"SMB domain (optional):", type:"entry", value:"");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

smb_login = script_get_preference("SMB login:");
smb_password = script_get_preference("SMB password:");
smb_domain = script_get_preference("SMB domain (optional):");

if (smb_login) set_kb_item(name: "SMB/login_filled/0", value: smb_login);
if (smb_password) set_kb_item(name:"SMB/password_filled/0", value:smb_password);
if (smb_domain) set_kb_item(name: "SMB/domain_filled/0", value: smb_domain);
