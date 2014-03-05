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
package ClamTk::Results;

# use strict;
# use warnings FATAL => 'all';
$| = 1;

use File::Basename 'basename', 'dirname';
use File::Copy 'move';
use Digest::MD5 'md5_hex';
use Encode;

use Gtk2::SimpleList;
use Glib 'TRUE', 'FALSE';

use Locale::gettext;
use POSIX 'locale_h';

use bytes;
binmode( STDIN,  ':utf8' );
binmode( STDOUT, ':utf8' );

my $slist;
my $hover_label;
my $hash;

# We have to avoid parsing mail for now:
# http://clamtk.sourceforge.net/faq.html#inbox
my $maildirs = join( '|',
    '.thunderbird', '.mozilla-thunderbird', 'evolution(?!/tmp)',
    'Mail',         'kmail',                "\.pst" );

sub display {
    shift;    # don't need package name
    ($hash) = @_;

    my $popup = Gtk2::Dialog->new( gettext('Scanning Results'),
        undef, 'destroy-with-parent' );
    $popup->signal_connect( destroy => sub { $popup->destroy } );
    $popup->set_default_size( 650, 250 );
    $popup->set_title( gettext('Scanning Results') );

    my ( $x, $y ) = ClamTk::GUI->window_coords();
    $popup->move( $x, $y );

    my $pbox = Gtk2::VBox->new();
    $popup->get_content_area()->add($pbox);
    $hover_label =
        Gtk2::Label->new( gettext('Possible threats have been found.') );
    $pbox->pack_start( $hover_label, FALSE, TRUE, 0 );

    # This scrolled window holds the slist
    my $scrolled_win = Gtk2::ScrolledWindow->new;
    $pbox->pack_start( $scrolled_win, TRUE, TRUE, 0 );
    $scrolled_win->set_shadow_type('etched_in');
    $scrolled_win->set_policy( 'never', 'automatic' );

    $slist = Gtk2::SimpleList->new(
        gettext('File')         => 'markup',
        gettext('Status')       => 'markup',
        gettext('Action Taken') => 'markup',
        );
    $scrolled_win->add($slist);
    $scrolled_win->grab_focus();

    $slist->get_selection->set_mode('multiple');
    $slist->set_rules_hint(TRUE);
    $slist->set_headers_clickable(TRUE);

    # No longer reorderable due to the way we
    # push these onto the $slist->{data}.
    # $slist->set_reorderable(TRUE);
    map { $_->set_resizable(TRUE) } $slist->get_columns;
    map { $_->set_sizing('fixed') } $slist->get_columns;
    map { $_->set_expand(TRUE) } $slist->get_columns;

    # Sorting the columns.
    # Can't do it yet because it dorks up the sexy highlighting
    # after quarantining or deleting a file.
    #for ( 0 .. 2 ) {
    #    $slist->get_column($_)->set_sort_column_id($_);
    #}

    $slist->set(
        hover_selection => TRUE,
        hover_expand    => TRUE
        );

    # Display the possible infections:
    # for my $keys ( sort keys %$hash ) {
    my $i = 0;
    while ( $i <= scalar keys %$hash ) {
        push @{ $slist->{data} },
            [
            $hash->{$i}->{name}, $hash->{$i}->{status},
            $hash->{$i}->{action},
            ];
        $i++;
        Gtk2->main_iteration while ( Gtk2->events_pending );
        last if ( $i == scalar keys %$hash );
    }

    # Left-click will clear the top label
    $slist->signal_connect(
        button_press_event => sub {
            my ( $widget, $event ) = @_;
            return FALSE unless $event->button == 1;
            $hover_label->set_text('');
        } );

    # Right-click functionality. Also uses 'sub confirm'.
    $slist->signal_connect(
        button_press_event => sub {
            my ( $widget, $event ) = @_;
            return FALSE unless $event->button == 3;
            my @sel   = $slist->get_selected_indices;
            my $deref = $sel[0];
            defined $deref or return;

            my $menu = Gtk2::Menu->new();

            # Right-click 'quarantine' option
            my $quar_pop =
                Gtk2::ImageMenuItem->new( gettext('Quarantine this file') );
            my $quar_image =
                Gtk2::Image->new_from_stock( 'gtk-refresh', 'menu' );
            $quar_pop->set_image($quar_image);
            $quar_pop->signal_connect(
                activate => sub {
                    for my $t (@sel) {
                        next if ( $hash->{$t}->{name} =~ m#$maildirs# );
                        next if ( -d $hash->{$t}->{name} );
                        main_confirm( $t, 'q' );
                    }
                } );
            $quar_pop->show();
            $menu->append($quar_pop)
                unless dirname( $hash->{$deref}->{name} )
                    =~ /^\/(proc|sys|dev)/;

            # Right-click 'delete' option
            my $delete_pop =
                Gtk2::ImageMenuItem->new( gettext('Delete this file') );
            my $del_image =
                Gtk2::Image->new_from_stock( 'gtk-delete', 'menu' );
            $delete_pop->set_image($del_image);
            $delete_pop->signal_connect(
                activate => sub {
                    for my $u (@sel) {
                        next if ( $hash->{$u}->{name} =~ m#$maildirs# );
                        next if ( -d $hash->{$u}->{name} );
                        main_confirm( $u, 'd' );
                    }
                } );
            $delete_pop->show();
            $menu->append($delete_pop)
                unless dirname( $hash->{$deref}->{name} )
                    =~ /^\/(proc|sys|dev)/;

            # Right-click 'save-as' option.
            # This is useful if the file is 'opened' (intercepted)
            # as a $web_browser download
            my $save_pop =
                Gtk2::ImageMenuItem->new_from_stock( 'gtk-save-as', undef );
            $save_pop->signal_connect(
                activate => sub {
                    return if ( -d $slist->{data}[$deref][0] );
                    my $save_dialog = Gtk2::FileChooserDialog->new(
                        gettext('Save As...'), undef, 'save',
                        'gtk-cancel' => 'cancel',
                        'gtk-ok'     => 'ok',
                        );
                    $save_dialog->set_do_overwrite_confirmation(TRUE);
                    $save_dialog->set_default_response('ok');

                    if ( "ok" eq $save_dialog->run ) {
                        my $tmp = $save_dialog->get_filename;
                        $save_dialog->destroy();
                        move( $slist->{data}[$deref][0], $tmp )
                            or do {
                            show_message_dialog( $popup, 'error', 'close',
                                gettext('Could not save that file.') );
                            return FALSE;
                            };
                        $slist->{data}[$deref][2] = gettext('Moved');
                        main_confirm( $deref, 's' );
                        show_message_dialog( $popup, 'info', 'close',
                            gettext('File saved.') );
                        return FALSE;
                    } else {
                        $save_dialog->destroy();
                    }
                } );
            $save_pop->show();
            $menu->append($save_pop);

            # Right-click 'cancel' option
            my $cancel_pop =
                Gtk2::ImageMenuItem->new_from_stock( 'gtk-cancel', undef );
            $cancel_pop->signal_connect( activate => sub { return; } );
            $cancel_pop->show();
            $menu->append($cancel_pop);
            $menu->popup( undef, undef, undef, undef, $event->button,
                $event->time );

            return TRUE;
        } );

    my $bottombar = Gtk2::Toolbar->new;
    $bottombar->set_style('both-horiz');
    $pbox->pack_start( $bottombar, FALSE, FALSE, 0 );

    my $quar_img = Gtk2::Image->new_from_stock( 'gtk-refresh', 'menu' );
    my $quar_btn = Gtk2::ToolButton->new( $quar_img, gettext('Quarantine') );
    $quar_btn->set_is_important(TRUE);
    $bottombar->insert( $quar_btn, -1 );
    $quar_btn->signal_connect(
        clicked => sub {
            my @sel = $slist->get_selected_indices;
            for my $t (@sel) {
                next if ( $hash->{$t}->{name} =~ m#$maildirs# );
                next if ( -d $hash->{$t}->{name} );
                main_confirm( $t, 'q' );
            }
        } );

    my $del_close_btn = Gtk2::ToolButton->new_from_stock('gtk-delete');
    $del_close_btn->set_is_important(TRUE);
    $bottombar->insert( $del_close_btn, -1 );
    $del_close_btn->signal_connect(
        clicked => sub {
            my @sel = $slist->get_selected_indices;
            for my $u (@sel) {
                next if ( $hash->{$u}->{name} =~ m#$maildirs# );
                next if ( -d $hash->{$u}->{name} );
                main_confirm( $u, 'd' );
            }
        } );

    my $b_sep = Gtk2::SeparatorToolItem->new;
    $b_sep->set_draw(FALSE);
    $b_sep->set_expand(TRUE);
    $bottombar->insert( $b_sep, -1 );

    my $results_close_btn = Gtk2::ToolButton->new_from_stock('gtk-close');
    $results_close_btn->set_is_important(TRUE);
    $bottombar->insert( $results_close_btn, -1 );
    $results_close_btn->signal_connect(
        clicked => sub {
            $popup->destroy;
        } );

    $popup->show_all();
    $slist->columns_autosize;
}

sub main_confirm {
    # This sub accepts both quarantine and delete options.
    # The quarantine happens without prompting, but deleting
    # always prompts the user.
    # $number = row of selected file so we can reference it
    # $do_this = quarantine, delete
    my $number  = shift;
    my $do_this = shift;

    #my $full_name = $slist->{data}[$number][0];
    my $full_name = $hash->{$number}->{name};
    my $md5sum    = $hash->{$number}->{md5sum};
    my $status    = $slist->{data}[$number][1];
    my $action    = $slist->{data}[$number][2];

    # do_this = quarantine (q), delete (d), or save (s).
    # The #CCCCCC color gives a neat grayed-out look
    # once the file is quarantined, deleted, or saved
    if ( $do_this eq 'q' ) {
        if ( not -e $full_name ) {
            $hover_label->set_text(
                sprintf gettext('File has been moved or deleted already.') );
            main_slist_delete($number);
            return;
        }
        if ( move_to_quarantine($number) ) {
            $hover_label->set_text( gettext('File has been quarantined.') );
            $slist->{data}[$number][2] =
                sprintf gettext("<b>Quarantined</b>");
        } else {
            $hover_label->set_text(
                gettext('File could not be quarantined.') );
            return;
        }
    } elsif ( $do_this eq 'd' ) {
        if ( not -e $full_name ) {
            $hover_label->set_text(
                gettext('File has been moved or deleted already.') );
            main_slist_delete($number);
            return;
        }
        my $confirm_message = gettext('Really delete this file?');
        $confirm_message .= ' ' . '(' . basename($full_name) . ')';
        my $confirm =
            Gtk2::MessageDialog->new( undef, [qw(modal destroy-with-parent)],
            'question', 'ok-cancel', $confirm_message );

        if ( 'cancel' eq $confirm->run ) {
            $confirm->destroy;
            return;
        } else {
            $confirm->destroy;
            if ( unlink($full_name) ) {
                $hover_label->set_text( gettext('File has been deleted.') );
                $slist->{data}[$number][2] =
                    sprintf gettext("<b>Deleted</b>");
            } else {
                $hover_label->set_text(
                    gettext('File could not be deleted.') );
                return;
            }
        }
    } elsif ( $do_this eq 's' ) {
        my $new_action = gettext('Moved');
        $slist->{data}[$number][0] =
            "<span foreground='#CCCCCC'>$full_name</span>";
        $slist->{data}[$number][1] =
            "<span foreground='#CCCCCC'>$status</span>";
        $slist->{data}[$number][2] =
            "<span foreground='#CCCCCC'><b>$new_action</b></span>";
        return;
    }
    main_slist_delete($number);
    return;
}

sub main_slist_delete {
    my $number = shift;
    #my $full_name = $slist->{data}[$number][0];
    my $full_name = $hash->{$number}->{name};
    my $status    = $slist->{data}[$number][1];
    my $action    = $slist->{data}[$number][2];
    $slist->{data}[$number][0] =
        "<span foreground='#CCCCCC'>$full_name</span>";
    $slist->{data}[$number][1] = "<span foreground='#CCCCCC'>$status</span>";
    $slist->{data}[$number][2] = "<span foreground='#CCCCCC'>$action</span>";
    #$popup->queue_draw;
    return;
}

sub move_to_quarantine {
    # $number = row we're dealing with
    my $number = shift;

    # We need the basename, because we're
    # dealing with the filename, not the full_path
    #my $full_name = $slist->{data}[$number][0];
    #my $basename  = basename($slist->{data}[$number][0]);
    my $full_name = $hash->{$number}->{name};
    my $basename  = basename($full_name);

    # This is where threats go
    my $paths = ClamTk::App->get_path('viruses');

    # Ensure quarantine directory exists
    if ( not -e $paths or not -d $paths ) {
        show_message_dialog( undef, 'info', 'close',
            gettext('Quarantine directory does not exist.') );
        return;
    }

    # Get permissions
    my $mode = ( stat($full_name) )[2];
    my $perm = sprintf( "%03o", $mode & oct(7777) );

    # Assign 600 permissions
    chmod oct(600), $full_name;
    move( $full_name, "$paths/$basename" ) or do {
        # When a 'mv' fails, it still probably did a 'cp'...
        # 'mv' copies the file first, then unlinks the source.
        # d'oh... so just to make sure, unlink the intended target
        # and THEN return.  No need to check for failure.
        unlink("$paths/$basename");
        return;
    };

    # Update restore file by adding file, path and md5
    my $ctx = do {
        local $/ = undef;
        open( my $F, '<', "$paths/$basename" ) or do {
            warn "Could not open file for md5-ing: $!\n";
            return;
        };
        binmode($F);
        <$F>;
    };
    my $md5 = md5_hex($ctx);

    ClamTk::Prefs->restore( $md5, 'add', $full_name, $perm );

    if ( not -e $full_name ) {
        return 1;
    } else {
        return -1;
    }
}

sub show_message_dialog {
    my ( $parent, $type, $button, $message ) = @_;

    my $dialog;
    $dialog =
        Gtk2::MessageDialog->new_with_markup( $parent,
        [qw(modal destroy-with-parent)],
        $type, $button, $message );

    $dialog->run;
    $dialog->destroy;
    return;
}

1;
