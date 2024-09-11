
# LICENSE

This software is braught to you under the EUPL-1.2 (or later) license.
The text of this license can be found in the LICENSES directory.

# Open Console

The software for Open Console is spread of multiple repositories:
  * <https://github.com/Skrodon/open-console-core> Core (required)
  * <https://github.com/Skrodon/open-console-owner> Owner Website
  * <https://github.com/Skrodon/open-console-connect> Connection provider
  * <https://github.com/Skrodon/open-console-tasks> batch processing (this repo)

# Open Console, Tasks managate
 
Open Console is a larger project: this sub-project only focusses on the batch-processing tasks.

Tasks are introduce to off-load computation intensive and slow work from the website processes onto separate processes.  The parallellization of this work can be monitored and managed via minion.

## Installing Perl modules

  * You may be able to install most of the required Perl packages from your distribution.  (When you have tried this, please contribute that list for inclusion here.  See the `Makefile.PL` for the list of required modules.)
  * Use Perl to install it for you:
	  * in the GIT extract of this code, run "perl Makefile.PL; make install`.  (You probably need super-admin rights to do this: depends on your Perl set-up)

# Developers
