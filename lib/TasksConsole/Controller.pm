# SPDX-FileCopyrightText: 2024 Mark Overmeer <mark@open-console.eu>
# SPDX-License-Identifier: EUPL-1.2-or-later

package TasksConsole::Controller;
use Mojo::Base 'Mojolicious::Controller';

use Log::Report 'open-console-owner';

=chapter NAME

TasksConsole::Controller - base-class for all task controllers

=chapter SYNOPSIS

=chapter DESCRIPTION

=chapter METHODS

=section Constructors
=cut

#------------------
=section Attributes

=cut

#------------------
=section Tasks

=method startJob $task, \%params, %options
Order Minion to run the named $task.  The task gets the jobid and the (reference
to a) HASH with data to be processed.  Returned is a jobid, local to this server
instance.
=cut

sub startJob($$%)
{	my ($self, $task, $params, %args) = @_;

	# Calling parameters are always an ARRAY in the database, altough we
	# pass only a single HASH.
	my $jobid = $self->minion->enqueue($task, [ $params ]);
}

1;