# tracker

This is 'process tracker' project.


# Formatting

This file will be primarily viewed in primitive Linux text console.
Rendering in browser is secondary.


# Task overview

I don't like some daemons (for example at-spi2-registry, gvfsd-http,
udisksd). Unfortunately I can't just uninstall them because some
applications which I use depend on those daemons. Usually I periodically
manually kill those daemons. I can setup 'cron job' to automatically kill
them. But I want special tool with some specific features...

We will need Linux kernel module which will track 'fork', 'exec' and
'exit' events in Linux kernel.

We will need user space application which will react on events reported
by kernel module and will decide when and what to do with different
processes.

We will need configuration file which will specify which daemon shall be
killed and how soon it shall happen.


# Future plans

Our tool can be used by 'parents' to control how much time 'childern' may
spend playing computer games.
