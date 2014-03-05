# ClamTk, copyright (C) 2004-2012 Dave M
#
# This file is part of ClamTk (http://clamtk.sourceforge.net).
#
# ClamTk is free software; you can redistribute it and/or modify it
# under the terms of either:
#
# a) the GNU General Public License as published by the Free Software
# Foundation; either version 1, or (at your option) any later version, or
#
# b) the "Artistic License".
package ClamTk::Device;
# We can't do realtime monitoring of devices
# (like an option to popup an alert when a device is plugged in)
# because we'd need Net::DBus::GLib - not available on many
# distros.
# Also, hal is deprecated:
# http://en.wikipedia.org/wiki/HAL_%28software%29
# (Version 5.x will have directory monitoring, though.)
# So, we'll use udev.  We're not going to monitor anything; rather,
# check what udev is reporting, and then see if it has a mountpoint.

# use strict;
# use warnings FATAL => 'all';
$| = 1;

use Glib 'TRUE', 'FALSE';

use Cwd 'realpath';
use Locale::gettext;
use POSIX 'locale_h';

sub look_for_device {
    # Get the coordinates of the parent window.
    my ( undef, $x, $y ) = @_;

    # Can't do set_size_request here because the window ($dwin)
    # won't expand based on # of devices found
    my $dwin = Gtk2::Dialog->new;
    $dwin->set_title( gettext('Virus Scanner') );
    $dwin->signal_connect( destroy => sub { $dwin->destroy } );
    $dwin->move( $x, $y );

    if ( -e '/usr/share/pixmaps/clamtk.png' ) {
        $dwin->set_default_icon_from_file('/usr/share/pixmaps/clamtk.png');
    } elsif ( -e '/usr/share/pixmaps/clamtk.xpm' ) {
        $dwin->set_default_icon_from_file('/usr/share/pixmaps/clamtk.xpm');
    }
    my $dbox = Gtk2::VBox->new( FALSE, 5 );
    $dwin->get_content_area()->add($dbox);
    Gtk2->main_iteration while ( Gtk2->events_pending );

    # The following are for images/language purposes
    my $cd_label     = gettext('CD/DVD');
    my $usb_label    = gettext('USB device');
    my $floppy_label = gettext('Floppy disk');

    # %devices will list everything we find
    my %devices = get_listing();

    # By now we'll know whether or not udev is installed.
    # Just leave if it's not there. Technically, they shouldn't
    # arrive this far anyway, so no big whoop.
    # return unless $cmd;

    # Return unless we have devices.
    # This could get confusing for users not
    # understanding the 'mount' thing.
    if ( !scalar( keys %devices ) ) {
        my $mount_msg = gettext('No devices were found.');
        $mount_msg .= "\n\n";
        $mount_msg
            .= gettext(
            'If you have connected a device, you may need to mount it first.'
            );
        show_message_dialog( $dwin, 'info', 'ok', gettext($mount_msg), $x,
            $y );
        $dwin->destroy;
        return 0;
    }

    # Technically Gtk2::Widget has a $widget->set_tooltip_markup()
    # method, but CentOS's Gtk2 is too old to support it.
    my $tt = Gtk2::Tooltips->new();

    my $dframe = Gtk2::Frame->new( gettext('Devices available') );
    $dbox->pack_start( $dframe, TRUE, TRUE, 0 );
    $dframe->set_border_width(5);
    $dframe->set_shadow_type('etched-in');

    # This is much better as a tooltip...
    # an extra label skews the display.
    $tt->set_tip( $dframe, gettext('Select a device or press Cancel') );

    # This toolbar will hold the devices found.
    my $m_tb = Gtk2::Toolbar->new;
    $m_tb->set_show_arrow(FALSE);
    $dframe->add($m_tb);

    # Get the information from the devices for display
    for my $d ( keys %devices ) {
        my ($label)  = $devices{$d}{MODEL};
        my ($mount)  = $devices{$d}{mount};
        my ($device) = $devices{$d}{label};

        # Now figure out which icon we need, based on the device found.
        my $gui_img = Gtk2::Image->new_from_stock(
              ( $device eq $cd_label )     ? 'gtk-cdrom'
            : ( $device eq $usb_label )    ? 'gtk-harddisk'
            : ( $device eq $floppy_label ) ? 'gtk-floppy'
            : '',
            'large-toolbar'
            );
        my $gui_btn = Gtk2::ToolButton->new( $gui_img, $label );
        $gui_btn->set_expand(TRUE);
        $tt->set_tip( $gui_btn, "$device ($mount)" );
        $gui_btn->signal_connect(
            clicked => sub {
                $dwin->destroy;
                ClamTk::GUI->getfile( 'device', $mount );
            } );
        $m_tb->insert( $gui_btn, -1 );
    }

    # This is trickery to add a line-spacer widget when
    # there are two or more items.  It's a sneaky way of
    # doing an "exists" on an array.  Well, not sneaky,
    # but I'm still proud of the fact that I was able to write it.
    # Anyway, don't operate on the toolbar (and its children)
    # directly despite that it returns a list; rather, we'll just
    # use an array - if another array item exists after the current,
    # add a spacer.
    if ( scalar( $m_tb->get_children ) > 1 ) {
        my @children = $m_tb->get_children;
        for my $child ( 0 .. $#children ) {
            my $needle = $child + 1;
            if ( $children[$needle] ) {
                $m_tb->insert( Gtk2::SeparatorToolItem->new, $child + 1 );
            }
        }
    }

    # This toolbar holds the close ('cancel') button.
    # A future option might be 'Help' for mounting devices.
    my $bottom_row = Gtk2::Toolbar->new();
    $dbox->pack_start( $bottom_row, FALSE, FALSE, 2 );
    $bottom_row->set_style('both-horiz');

    my $sep = Gtk2::SeparatorToolItem->new;
    $sep->set_draw(FALSE);
    $sep->set_expand(TRUE);
    $bottom_row->insert( $sep, -1 );

    # Cancel button for devices
    my $cancel = Gtk2::ToolButton->new_from_stock('gtk-close');
    $cancel->set_is_important(TRUE);
    $bottom_row->insert( $cancel, -1 );
    $cancel->signal_connect(
        clicked => sub {
            $dwin->destroy;
            return 0;
        } );
    # Give the cancel button the focus;
    # looks better than when a device has it.
    # It also allows the user to press enter
    # to kill the window.
    $cancel->can_focus(TRUE);
    $cancel->grab_focus();

    # If there's only one device, set the size of the window.
    # Otherwise it's too small.
    if ( scalar( keys %devices ) == 1 ) {
        $dwin->set_size_request( 200, 150 );
        $dwin->queue_draw();
    }

    $dwin->show_all();
    return;
}

sub get_listing {
    my %hash;

    my $cmd = get_udev_cmd();
    return unless $cmd;

    my $path = '/dev/disk/by-path';
    my @pop  = glob "$path/*";

    for my $f (@pop) {
        $hash{$f}{realpath} = realpath($f);

        my $run = $cmd . $hash{$f}{realpath};

        open( my $T, '-|', $run ) or do {
            warn "Problems running $cmd in Device: $!\n";
            return;
        };

        while (<$T>) {
            # Skip blank lines
            next if (/^$/);
            # Skip udevadm intro.  This only happens because we
            # use the '--attribute-walk' argument with udevadm.
            next if (/^Udev/);
            next if (/^walks up the chain/);
            next if (/^found, all/);
            next if (/^A rule to match,/);
            next if (/^and the attributes/);
            # Chomp newline
            chomp;

            # First we'll look for udevadm things.

            # This one can tip us to what it is (cd, floppy, etc):
            if (/KERNEL=="(.*?)"$/) {
                $hash{$f}{KERNEL} = $1
                    unless defined( $hash{$f}{KERNEL} );
            }
            # This can be the difference between a
            # USB hard disk and USB thumb drive.
            if (/ATTRS?{removable}=="(.)"$/) {
                $hash{$f}{REMOVABLE} = $1;
            }
            # This is good for label stuff:
            if (/ATTRS{vendor}=="(.*?)"$/) {
                next if ( defined $hash{$f}{VENDOR} );
                $hash{$f}{VENDOR} = $1;
            }
            # This is good for showing us if it's USB:
            if (/DRIVERS=="(.*?)"$/) {
                $hash{$f}{DRIVERS} = $1
                    unless ( !$1 );
            }
            # This is good for display purposes:
            if (/ATTRS{model}=="(.*?)"$/) {
                $hash{$f}{MODEL} = $1;
            }

            # Now we'll look for udevinfo things:
            if (/N: (.*?)$/) {
                $hash{$f}{KERNEL} = $1;
            }
            # ID_VENDOR doesn't show up in CDs that I've seen
            if (/ID_VENDOR=(.*?)$/) {
                $hash{$f}{VENDOR} = $1;
            }
            # One of the next two should grab something:
            if (/ID_MODEL=(.*?)$/) {
                $hash{$f}{MODEL} = $1;
            }
            if (/ID_FS_LABEL_SAFE=(.*?)$/) {
                $hash{$f}{MODEL} = $1;
            }
            # This is important to ensure we're
            # grabbing something USB:
            if (/ID_BUS=(.*?)$/) {
                $hash{$f}{DRIVERS} = $1;
            }
            if (m{disk/by-uuid/(.*?)$}) {
                $hash{$f}{CONTINUE} = $1;
            }
            if (/ID_TYPE=(.*?)$/) {
                $hash{$f}{id_type} = $1;
                $hash{$f}{CONTINUE} = $1 if ( $1 eq 'floppy' );
            }

        }

        # If there are no DRIVERS, it's probably
        # not the device we're looking for.
        if ( !$hash{$f}{DRIVERS} ) {
            delete $hash{$f};
            next;
        }

        # If it's a disk but not a USB disk, remove it.
        if ( exists $hash{$f}{id_type} ) {
            if ( $hash{$f}{id_type} eq 'disk' ) {
                if ( $hash{$f}{DRIVERS} ne 'usb' ) {
                    delete $hash{$f};
                    next;
                }
            }
        }

        # udevadm lets us know if a device is removable
        # or not. For us, that means the difference between
        # a USB hard disk and USB flash drive.
        if ( exists( $hash{$f}{REMOVABLE} ) ) {
            if ( $hash{$f}{REMOVABLE} == 0 ) {
                delete $hash{$f};
                next;
            }
        }
        # For udevinfo, we need (e.g.) sdc1 vice sdc.
        # The difference is distinguished (as best I can
        # tell) with sdc1 having the by-uuid section. These
        # files end with .part[0-9].
        if (    $cmd =~ /udevinfo/
            and $hash{$f}{DRIVERS} =~ /usb/
            and not exists( $hash{$f}{CONTINUE} ) ) {
            delete $hash{$f};
            next;
        }

        # The easiest way to determine what we have is
        # from udevinfo's id_type.  We'll also look at the KERNEL
        # and guess - hoping fd == floppy and sr == cd.  The
        # DRIVERS option should catch USB devices like flashdrives
        # and mp3 players.
        $hash{$f}{label} =
              ( $hash{$f}{KERNEL} =~ /fd[0-9]/ ) ? gettext('Floppy disk')
            : ( $hash{$f}{KERNEL} =~ /sr[0-9]/ ) ? gettext('CD/DVD')
            : ( $hash{$f}{DRIVERS} =~ /usb|ehci_hcd/ ) ? gettext('USB device')
            : ( $hash{$f}{id_type} =~ /cd/ )           ? gettext('CD/DVD')
            : ( $hash{$f}{id_type} =~ /floppy/ ) ? gettext('Floppy disk')
            :                                      '';

        # This is a double-check to ensure we have a mount point.
        # If not, remove whatever we picked up.
        $hash{$f}{mount} = mountpoint( $hash{$f}{realpath} );
        if ( $hash{$f}{mount} eq 'undef' ) {
            delete $hash{$f};
            next;
        }
    }
    return %hash;
}

sub mountpoint {
    my $find_this = shift;
    # /proc/mounts seems to be pretty universal
    # with Linux for determining mountpoints
    my $file = '/proc/mounts';

    open( my $P, '<', $file ) or return 'undef';
    while (<$P>) {
        # $_ will look like this:
        # /dev/fd0	/media/floppy	vfat	...
        # We just need the first two values:
        my ( $dev, $mount ) = ( split(/\s+/) )[ 0, 1 ];
        if ( $dev eq $find_this ) {
            # /proc/mounts may contain octal representations
            # of spaces, tabs, newlines and backslashes
            # Look for and replace spaces:
            $mount =~ s/(\\040)/ /g;
            # Look for and replace tabs:
            $mount =~ s/(\\011)/\t/g;
            # Look for and replace newlines:
            $mount =~ s/(\\012)/\n/g;
            # Look for and replace backslashes:
            $mount =~ s/(\\134)/\\/g;
            return $mount;
        }
    }
    return 'undef';
}

sub get_udev_cmd {
    # We'll use either udevadm or udevinfo.
    # Checking for udevadm first:
    local $ENV{'PATH'} = '/bin:/usr/bin:/sbin';
    delete @ENV{ 'IFS', 'CDPATH', 'ENV', 'BASH_ENV' };
    my $path  = '';
    my $which = 'which';
    my $adm   = 'udevadm';

    if ( open( my $c, '-|', $which, $adm ) ) {
        while (<$c>) {
            chomp;
            $path = $_ if ( -e $_ );
            # If we remove the '--attribute-walk' argument, the info
            # would be parsed similar to udevinfo and we could shorten
            # this file a bit.  However, it lacks the 'removable' field,
            # which is how we distinguish between a hard disk and
            # a flashdrive...
            $path .= ' info --query=all --attribute-walk --name=';
        }
    }

    if ( !$path ) {
        $adm = 'udevinfo';
        if ( open( my $c, '-|', $which, $adm ) ) {
            while (<$c>) {
                chomp;
                $path = $_ if ( -e $_ );
                $path .= ' -q all -n ';
            }
        }

    }

    return $path;
}

sub show_message_dialog {
    my ( $parent, $type, $button, $message, $x, $y ) = @_;
    # $parent = $dwin
    # $type = info, warning, error, question
    # $button = ok, ok-cancel, close, ...
    # $message = <a message>
    # $x, $y = coords

    my $dialog;
    $dialog =
        Gtk2::MessageDialog->new_with_markup( $parent,
        [qw(modal destroy-with-parent)],
        $type, $button, $message );

    $dialog->move( $x, $y ) if ( $x && $y );
    $dialog->run;
    $dialog->destroy;
    return;
}

1;
