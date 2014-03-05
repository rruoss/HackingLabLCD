###############################################################################
# $Id: os_eol.inc 15639 2013-03-07 14:27:05Z mime $
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

eol_urls = make_array();
eol_cpes = make_array();

# See gather-package-list.nasl for valid/known linux cpes

# OpenSUSE (http://en.opensuse.org/Lifetime)
eol_urls['cpe:/o:novell:opensuse'] = 'http://en.opensuse.org/Lifetime';
eol_cpes['cpe:/o:novell:opensuse:11.4'] = '05 Nov 2012';
eol_cpes['cpe:/o:novell:opensuse:11.3'] = '20 Jan 2012';
eol_cpes['cpe:/o:novell:opensuse:11.2'] = '12 May 2011';
eol_cpes['cpe:/o:novell:opensuse:11.1'] = '31 Dec 2010';
eol_cpes['cpe:/o:novell:opensuse:11.0'] = '30 Jun 2010';
eol_cpes['cpe:/o:novell:opensuse:10.3'] = '31 Oct 2009';
eol_cpes['cpe:/o:novell:opensuse:10.2'] = '30 Nov 2008';

# SLES (http://www.softpanorama.org/Commercial_linuxes/Suse/sles_life_cycle.shtml)
eol_urls['cpe:/o:suse:linux_enterprise_server'] = 'http://www.softpanorama.org/Commercial_linuxes/Suse/sles_life_cycle.shtml';
eol_cpes['cpe:/o:suse:linux_enterprise_server:9'] = '31 Jul 2011';

# Ubuntu (https://wiki.ubuntu.com/Releases)
eol_urls['cpe:/o:canonical:ubuntu_linux'] = 'https://wiki.ubuntu.com/Releases';
eol_cpes['cpe:/o:canonical:ubuntu_linux:11.04'] = '28 Oct 2012';
eol_cpes['cpe:/o:canonical:ubuntu_linux:10.10'] = '10 Apr 2012';
eol_cpes['cpe:/o:canonical:ubuntu_linux:9.10']  = '30 Apr 2011';
eol_cpes['cpe:/o:canonical:ubuntu_linux:9.04']  = '23 Oct 2010';
eol_cpes['cpe:/o:canonical:ubuntu_linux:8.10']  = '12 May 2011';
eol_cpes['cpe:/o:canonical:ubuntu_linux:7.10']  = '18 Apr 2009';
eol_cpes['cpe:/o:canonical:ubuntu_linux:7.04']  = 'Oct 2008';
eol_cpes['cpe:/o:canonical:ubuntu_linux:6.10']  = 'Apr 2008';
eol_cpes['cpe:/o:canonical:ubuntu_linux:6.06']  = '14 Jul 2009';
eol_cpes['cpe:/o:canonical:ubuntu_linux:5.10']  = 'Apr 2007';
eol_cpes['cpe:/o:canonical:ubuntu_linux:5.04']  = 'Oct 2006';
eol_cpes['cpe:/o:canonical:ubuntu_linux:4.10']  = 'Apr 2006';

# Red Hat Enterprise Linux (https://access.redhat.com/security/updates/eol/)
eol_urls['cpe:/o:redhat:enterprise_linux'] = 'https://access.redhat.com/security/updates/eol/';
eol_cpes['cpe:/o:redhat:enterprise_linux:4'] = 'unknown';
eol_cpes['cpe:/o:redhat:enterprise_linux:3'] = 'unknown';
eol_cpes['cpe:/o:redhat:enterprise_linux:2.1'] = 'unknown';

# Redhat Linux (http://en.wikipedia.org/wiki/Red_Hat_Linux)
eol_urls['cpe:/o:redhat:linux'] = 'http://en.wikipedia.org/wiki/Red_Hat_Linux';
eol_cpes['cpe:/o:redhat:linux:9'] = 'unknown';
eol_cpes['cpe:/o:redhat:linux:8.0'] = 'unknown';
eol_cpes['cpe:/o:redhat:linux:7.3'] = 'unknown';

# CentOS (http://wiki.centos.org/Download)
eol_urls['cpe:/o:centos:centos'] = 'http://wiki.centos.org/Download';
eol_cpes['cpe:/o:centos:centos:4'] = '29 Feb 2012';
eol_cpes['cpe:/o:centos:centos:3'] = '31 Oct 2010';
eol_cpes['cpe:/o:centos:centos:2'] = '31 May 2009';

# Fedora (https://fedoraproject.org/wiki/End_of_life?rd=LifeCycle/EOL)
eol_urls['cpe:/o:fedoraproject:fedora'] = 'https://fedoraproject.org/wiki/End_of_life?rd=LifeCycle/EOL';
eol_cpes['cpe:/o:fedoraproject:fedora:15'] = '26 Jun 2012';
eol_cpes['cpe:/o:fedoraproject:fedora:14'] = '09 Dec 2011';
eol_cpes['cpe:/o:fedoraproject:fedora:13'] = '24 Jun 2011';
eol_cpes['cpe:/o:fedoraproject:fedora:12'] = '12 Feb 2010';
eol_cpes['cpe:/o:fedoraproject:fedora:11'] = '25 Jun 2010';
eol_cpes['cpe:/o:fedoraproject:fedora:10'] = '19 Dec 2009';
eol_cpes['cpe:/o:fedoraproject:fedora:9']  = '10 Jul 2009';
eol_cpes['cpe:/o:fedoraproject:fedora:8']  = '07 Jan 2009';
eol_cpes['cpe:/o:fedoraproject:fedora:7']  = '13 Jun 2008';
eol_cpes['cpe:/o:fedoraproject:fedora_core:6'] = '27 Dec 2007';
eol_cpes['cpe:/o:fedoraproject:fedora_core:5'] = '02 Jul 2007';
eol_cpes['cpe:/o:fedoraproject:fedora_core:4'] = '07 Aug 2006';
eol_cpes['cpe:/o:fedoraproject:fedora_core:3'] = '16 Jan 2006';
eol_cpes['cpe:/o:fedoraproject:fedora_core:2'] = '11 Apr 2005';
eol_cpes['cpe:/o:fedoraproject:fedora_core:1'] = '20 Sep 2004';

# Debian # (http://en.wikipedia.org/wiki/Debian)
eol_urls['cpe:/o:debian:debian_linux'] = 'http://en.wikipedia.org/wiki/Debian';
eol_cpes['cpe:/o:debian:debian_linux:5.0'] = '06 Feb 2012';
eol_cpes['cpe:/o:debian:debian_linux:4.0'] = '15 Feb 2010';
eol_cpes['cpe:/o:debian:debian_linux:3.1'] = '31 Mar 2008';
eol_cpes['cpe:/o:debian:debian_linux:3.0'] = 'Aug 2006';
eol_cpes['cpe:/o:debian:debian_linux:2.2'] = 'Apr 2004';

# Mandriva (http://www.mandriva.com/en/support/lifecycle/)
eol_urls['cpe:/o:mandriva:linux'] = 'http://www.mandriva.com/en/support/lifecycle/';
eol_cpes['cpe:/o:mandriva:linux:2008.0'] = '09 Oct 2010';
eol_cpes['cpe:/o:mandriva:linux:2008.1'] = '15 Oct 2009';
eol_cpes['cpe:/o:mandriva:linux:2009.0'] = '15 Oct 2011';
eol_cpes['cpe:/o:mandriva:linux:2009.1'] = '29 Oct 2010';
eol_cpes['cpe:/o:mandriva:linux:2010.0'] = '03 Nov 2012';
eol_cpes['cpe:/o:mandriva:linux:2010.1'] = '08 Jul 2012';
eol_cpes['cpe:/o:mandriva:linux:2011.0'] = '29 Feb 2013';

# Mandrake
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:7.2'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:8.0'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:8.1'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:9.1'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:9.2'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:10.0'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:10.1'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:10.2'] = 'unknown';

# Slackware
eol_urls['cpe:/o:slackware:slackware_linux'] = 'http://alien.slackbook.org/blog/eol-for-old-releases/';
eol_cpes['cpe:/o:slackware:slackware_linux:8.1'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:9.0'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:9.1'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:10.0'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:10.1'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:10.2'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:11.0'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:12.0'] = 'unknown';


#Windows for Workgroups 3.1 (http://support.microsoft.com/lifecycle/?p1=3127)
eol_urls['cpe:/o:microsoft:windows:3.1'] = 'http://support.microsoft.com/lifecycle/?p1=3127';
eol_cpes['cpe:/o:microsoft:windows:3.1'] = '31 Dec 2001';

#Windows for Workgroups 3.11 (http://support.microsoft.com/lifecycle/?p1=3128)
eol_urls['cpe:/o:microsoft:windows:3.11'] = 'http://support.microsoft.com/lifecycle/?p1=3128';
eol_cpes['cpe:/o:microsoft:windows:3.11'] = '31 Dec 2001';

#Windows 95 (http://support.microsoft.com/lifecycle/search/default.aspx?sort=PN&alpha=Windows+95&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_95'] = 'http://support.microsoft.com/lifecycle/search/default.aspx?sort=PN&alpha=Windows+95&Filter=FilterNO';
eol_cpes['cpe:/o:microsoft:windows_95'] = '31 Dec 2001';
eol_cpes['cpe:/o:microsoft:windows_95::gold'] = '31 Dec 2001';
eol_cpes['cpe:/o:microsoft:windows_95::osr2'] = '31 Dec 2001';
eol_cpes['cpe:/o:microsoft:windows_95::osr2.1'] = '31 Dec 2001';
eol_cpes['cpe:/o:microsoft:windows_95::osr2.5'] = '31 Dec 2001';
eol_cpes['cpe:/o:microsoft:windows_95::sp1'] = '31 Dec 2001';
eol_cpes['cpe:/o:microsoft:windows_95::sr2'] = '31 Dec 2001';

#Windows 98 (http://support.microsoft.com/lifecycle/search/default.aspx?sort=PN&alpha=Windows+98&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_98'] = 'http://support.microsoft.com/lifecycle/search/default.aspx?sort=PN&alpha=Windows+98&Filter=FilterNO';
eol_cpes['cpe:/o:microsoft:windows_98'] = '11 Jul 2006';
eol_cpes['cpe:/o:microsoft:windows_98se'] = '11 Jul 2006';
eol_cpes['cpe:/o:microsoft:windows_98::gold'] = '11 Jul 2006';

#Windows Millennium Edition (http://support.microsoft.com/lifecycle/?p1=6519)
eol_cpes['cpe:/o:microsoft:windows_me'] = 'http://support.microsoft.com/lifecycle/?p1=6519';
eol_cpes['cpe:/o:microsoft:windows_me'] = '11 Jul 2006';
eol_cpes['cpe:/o:microsoft:windows_me::gold'] = '11 Jul 2006';

#Windows NT (http://support.microsoft.com/lifecycle/search/default.aspx?sort=PN&alpha=Windows+NT&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_nt'] = 'http://support.microsoft.com/lifecycle/search/default.aspx?sort=PN&alpha=Windows+NT&Filter=FilterNO';
eol_cpes['cpe:/o:microsoft:windows_nt:3.0.1'] = 'unknown';
eol_cpes['cpe:/o:microsoft:windows_nt:3.1'] = '31 Dec 2000';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5'] = 'unknown';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1:sp1'] = '30 Sep 2000';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1:sp2'] = '30 Sep 2000';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1:sp3'] = '30 Sep 2000';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1:sp4'] = '30 Sep 2000';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1:sp5'] = '30 Sep 2000';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1'] = '30 Sep 2000';
eol_cpes['cpe:/o:microsoft:windows_nt:3.51'] = '30 Sep 2000';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0'] = 'unknown';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:gold'] = 'unknown';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp1'] = 'unknown';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp2'] = 'unknown';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp3'] = 'unknown';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp4'] = 'unknown';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp5'] = 'unknown';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6'] = 'unknown';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6a'] = 'unknown';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:gold:workstation'] = '30 Jun 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:gold:server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:gold:enterprise'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:gold:terminal_server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp1:workstation'] = '30 Jun 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp2:workstation'] = '30 Jun 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp3:workstation'] = '30 Jun 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp4:workstation'] = '30 Jun 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp5:workstation'] = '30 Jun 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6:workstation'] = '30 Jun 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6a:workstation'] = '30 Jun 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp1:server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp2:server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp3:server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp4:server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp5:server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6:server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6a:server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp1:enterprise'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp2:enterprise'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp3:enterprise'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp4:enterprise'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp5:enterprise'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6:enterprise'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6a:enterprise'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp1:terminal_server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp2:terminal_server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp3:terminal_server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp4:terminal_server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp5:terminal_server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6:terminal_server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6a:terminal_server'] = '31 Dec 2002';

#Windows 2000 (http://support.microsoft.com/lifecycle/search/default.aspx?sort=PN&alpha=Windows+2000&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_2000'] = 'http://support.microsoft.com/lifecycle/search/default.aspx?sort=PN&alpha=Windows+2000&Filter=FilterNO';
eol_cpes['cpe:/o:microsoft:windows_2000'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::gold'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp1'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp2'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp3'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp4'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::gold:server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::gold:professional'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp1:advanced_server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp2:advanced_server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp3:advanced_server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp4:advanced_server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp1:datacenter_server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp2:datacenter_server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp3:datacenter_server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp4:datacenter_server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp1:professional'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp2:professional'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp3:professional'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp4:professional'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp1:server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp2:server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp3:server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp4:server'] = '13 Jul 2010';


function get_eol_url(cpe) {

  if(!cpe) return FALSE;

  if(eol_urls[cpe]) # for some windows cpes
    return eol_urls[cpe];

  _cpe = split(cpe,sep:":",keep:FALSE);

  if (_cpe && _cpe[0] && _cpe[1] && _cpe[2] && _cpe[3]) {
    cpe = _cpe[0] + ':' + _cpe[1] + ':' + _cpe[2] + ':' + _cpe[3];
  }  

  if(":-:lts" >< cpe) # for ubuntu lts
    cpe += ':-:lts';

  if(!eol_urls[cpe]) return FALSE;

  return eol_urls[cpe];

}

function get_eol_date(cpe) {

  if(!cpe) return FALSE;
  if(!eol_cpes[cpe]) return FALSE;

  eol_date = eol_cpes[cpe];

  if("unknown" >< eol_date) return FALSE;

  return eol_date;

}  

function build_eol_message(desc,cpe) {

  if(!cpe) return desc;

  eol_url = get_eol_url(cpe:cpe);
  eol_date = get_eol_date(cpe:cpe);

  message = 'The Operating System (' + cpe  + ') on the remote host has reached the end of life';
  
  if(eol_date)
    message +=  ' at ' + eol_date;

  message += '\nand should not be used anymore.';

  if(eol_url)
    message += '\nSee ' + eol_url + ' for more information.\n';

  return message;

}  
