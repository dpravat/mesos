#!/usr/bin/env python
# This is a wrapper around the 'post-review'/'rbt' tool provided by
# Review Board. This is currently used by Apache Mesos development.
#
# What does this do?
# It provides the ability to send a review for each commit on the
# current branch.
#
# Why is that useful?
# No one likes a 5000 line review request. Using this tool forces one
# to create logical commits which can be reviewed independently.
#
# How do I use it?
# First install 'RBTools' from Review Board.
# http://www.reviewboard.org/downloads/rbtools/
#
# $ cd /path/to/mesos
# $ [ do some work on your branch off of master, make commit(s) ]
# $ ./support/post-reviews.py --server=https://reviews.apache.org \
#   --tracking-branch=origin/master --target-groups=mesos --open
#
# NOTE: post-reviews is currently specific to Mesos development,
# but can easily be adapted for other projects.

import argparse
import atexit
import imp
import os
import re
import sys

from distutils.version import LooseVersion

from subprocess import check_output, Popen, PIPE, STDOUT

def execute(command, ignore_errors=False):
    process = None
    try:
        process = Popen(command,
                stdin=PIPE,
                stdout=PIPE,
                stderr=STDOUT,
                shell=False)
    except:
        if not ignore_errors:
            raise
        return None

    data, error = process.communicate()
    status = process.wait()
    if status != 0 and not ignore_errors:
        cmdline = ' '.join(command) if isinstance(command, list) else command
        need_login = \
          'Please log in to the Review Board server at reviews.apache.org.'
        if need_login in data:
          print need_login, '\n'
          print "You can either:"
          print "  (1) Run 'rbt login', or"
          print "  (2) Set the default USERNAME/PASSWORD in '.reviewboardrc'"
        else:
          print 'Failed to execute: \'' + cmdline + '\':'
          print data
        sys.exit(1)
    elif status != 0:
        return None
    return data

def user_skipped_review_win32():
    """Prints prompt asking whether to skip or post a reveiew, reports result.

    The can respond to the prompt with: a 'y', indicating we want to post the
    review; an 'n', indicating we want to skip the review; or Ctrl-D,
    indicating we want to terminate the script.

    On Unix, the user types Ctrl-C to skip a review. This approach doesn't
    work on Windows because the model for OS signals is totally different.
    The specific reason is detailed in[1]; our solution is to use a
    `getch`-like approach on Windows, where the user presses the 'y' or the
    'n' key to push the current review or skip it, respectively.

    The summary of the issue detailed in [1] is: when the user presses Ctrl-C,
    `fgets` returns EOF  immediately, but `errno` is not set to reflect the
    interrupt like it is on many Unixes. This causes an `EOFError` to be
    raised. Concurrently, the signal handler is called asynchronously on
    another thread, which causes the `KeyboardInterrupt` to be raised. Most
    of the time, the `EOFError` gets raised first and the user sees an
    `EOFError` followed by a `KeyboardInterrupt`, rather than just a
    `KeyboardInterrupt`. It is very hard to reliably route around this at the
    application level, so instead of writing complicated code to accomplish
    this, we just write replace the interface with an equally simple one that
    we know we can reliably support.

    [1] http://bugs.python.org/issue439992

    Returns:
        `True` if user asked to skip review, `False` otherwise.
    """
    import msvcrt
    ctrl_d = chr(4)

    print "\nPress 'y' to post, 'n' to skip, or ^D to exit.\n"

    choice = msvcrt.getch()

    # Loop until we get a 'y', and 'n', or a Ctrl-D.
    while choice != 'y' and choice != 'n' and choice != ctrl_d:
        print "Invalid choice. Press 'y' to continue or 'n' to skip or " + \
            "^D to abort."
        choice = msvcrt.getch()

    # Report the user choice.
    if choice == 'y':
        return False
    elif choice == ctrl_d:
        sys.exit(0)
    else:
        return True

def user_skipped_review_unix():
    """Prints prompt asking whether to skip or post a reveiew, reports result.

    The can respond to the prompt with: a '<RET>', indicating we want to post
    the review; or a Ctrl-C indicating we want to skip the review.

    Returns:
        `True` if user asked to skip review, `False` otherwise.
    """
    try:
        raw_input(
            "\nPress enter to continue or 'Ctrl-C' to skip.\n")
    except KeyboardInterrupt:
        return True
    return False

# The user review prompt is OS-specific; we set it here.
if os.name == 'nt':
    user_skipped_review = user_skipped_review_win32
else:
    user_skipped_review = user_skipped_review_unix

# On Windows, we need to call `rbt.cmd` instead of `rbt` the Bash script.
if os.name == 'nt':
    rbt_executable = 'rbt.cmd'
else:
    rbt_executable = 'rbt'

# TODO(hausdorff): We have disabled colors for the diffs on Windows, as piping
# them through `subprocess` causes us to emit ANSI escape codes, which the
# command prompt doesn't recognize. Presumably we are being routed through some
# TTY that causes git to not emit the colors using `cmd`'s color codes API
# (which is entirely different from ANSI. See [1] for more information and
# MESOS-3872.
#
# [1] http://stackoverflow.com/questions/5921556/in-git-bash-on-windows-7-colors-display-as-code-when-running-cucumber-or-rspec
if os.name == 'nt':
    creating_review_format = '--pretty=format:%H %d %s'
    updating_review_format = '--pretty=format:%H %d %s (%cr)'
    parent_log_format = '--pretty=format:%H %d %s (%cr)'
    history_log_format = '--pretty=format:%H %d %s (%cr)'
else:
    creating_review_format = '--pretty=format:%Cred%H%Creset -%C(yellow)%d%Creset %s'
    updating_review_format = '--pretty=format:%Cred%H%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr)%Creset'
    parent_log_format = '--pretty=format:%Cred%H%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr)%Creset'
    history_log_format = '--pretty=format:%Cred%H%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr)%Creset'

# TODO(benh): Make sure this is a git repository, apologize if not.

# Choose 'rbt' if available, otherwise choose 'post-review'.
post_review = None
rbt_version = execute([rbt_executable, '--version'], ignore_errors=True)
if rbt_version:
  rbt_version = LooseVersion(rbt_version)
  post_review = [rbt_executable, 'post']
elif execute(['post-review', '--version'], ignore_errors=True):
  post_review = ['post-review']
else:
  print 'Please install RBTools before proceeding'
  sys.exit(1)

# Don't do anything if people have unstaged changes.
diff_stat = execute(['git', 'diff', '--shortstat']).strip()

if diff_stat:
  print 'Please commit or stash any changes before using post-reviews!'
  sys.exit(1)

# Don't do anything if people have uncommitted changes.
diff_stat = execute(['git', 'diff', '--shortstat', '--staged']).strip()

if diff_stat:
  print 'Please commit staged changes before using post-reviews!'
  sys.exit(1)

# Grab a reference to the repo's git directory. Usually this is simply .git in
# the repo's top level directory. However, when submodules are used, it may
# appear elsewhere. The most up-to-date way of finding this directory is to use
# `git rev-parse --git-common-dir`. This is necessary to support things like
# git worktree in addition to git submodules. However, as of January 2016,
# support for the '--git-common-dir' flag is fairly new, forcing us to fall
# back to the older '--git-dir' flag if '--git-common-dir' is not supported. We
# do this by checking the output of `git rev-parse --git-common-dir` and seeing
# if it gives us a valid directory back. If not, we set the git directory using
# the '--git-dir' flag instead.
git_dir = execute(['git', 'rev-parse', '--git-common-dir']).strip()
if not os.path.isdir(git_dir):
  git_dir = execute(['git', 'rev-parse', '--git-dir']).strip()

# Grab a reference to the top level directory of this repo.
top_level_dir = execute(['git', 'rev-parse', '--show-toplevel']).strip()

# Use the tracking_branch specified by the user if exists.
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--server')
parser.add_argument('--tracking-branch')
args, _ = parser.parse_known_args()

# Try to read the .reviewboardrc in the top-level directory.
reviewboardrc_filepath = os.path.join(top_level_dir, '.reviewboardrc')
if os.path.exists(reviewboardrc_filepath):
    sys.dont_write_bytecode = True  # Prevent generation of '.reviewboardrcc'.
    reviewboardrc = imp.load_source('reviewboardrc', reviewboardrc_filepath)

reviewboard_url = (
    args.server if args.server else
    reviewboardrc.REVIEWBOARD_URL if 'REVIEWBOARD_URL' in dir(reviewboardrc) else
    'https://reviews.apache.org')

tracking_branch = (
    args.tracking_branch if args.tracking_branch else
    reviewboardrc.TRACKING_BRANCH if 'TRACKING_BRANCH' in dir(reviewboardrc) else
    'master')

branch_ref = execute(['git', 'symbolic-ref', 'HEAD']).strip()
branch = branch_ref.replace('refs/heads/', '', 1)

# do not work on master branch
if branch == "master":
    print "We're expecting you to be working on another branch from master!"
    sys.exit(1)

temporary_branch = '_post-reviews_' + branch

# Always delete the temporary branch.
atexit.register(lambda: execute(['git', 'branch', '-D', temporary_branch], True))

# Always put us back on the original branch.
atexit.register(lambda: execute(['git', 'checkout', branch]))

merge_base = execute(['git', 'merge-base', tracking_branch, branch_ref]).strip()



output = check_output([
    'git',
    '--no-pager',
    'log',
    history_log_format,
    merge_base + '..HEAD'])
print 'Running \'%s\' across all of ...' % " ".join(post_review)
print output

log = execute(['git',
               '--no-pager',
               'log',
               '--no-color',
               '--pretty=oneline',
               '--reverse',
               merge_base + '..HEAD']).strip()

if len(log) <= 0:
    print "No new changes compared with master branch!"
    sys.exit(1)

shas = []

for line in log.split('\n'):
    sha = line.split()[0]
    shas.append(sha)


previous = tracking_branch
parent_review_request_id = None
for i in range(len(shas)):
    sha = shas[i]

    execute(['git', 'branch', '-D', temporary_branch], True)

    message = execute(['git',
                       '--no-pager',
                       'log',
                       '--pretty=format:%s%n%n%b',
                       previous + '..' + sha])

    review_request_id = None

    pos = message.find('Review:')
    if pos != -1:
        # NOTE: Strip the trailing '/' off the URL so we don't generate a
        # pattern that looks for two slashes, e.g., `reviews.apache.org//r/`.
        url_pattern = "/".join([reviewboard_url.strip('/'), 'r', '[0-9]+'])
        pattern = re.compile('Review: ({url})$'.format(url=url_pattern))
        match = pattern.search(message.strip().strip('/'))

        if match is None:
            print "\nInvalid ReviewBoard URL: '{}'".format(message[pos:])
            sys.exit(1)

        url = match.group(1)
        review_request_id = os.path.basename(url)

    # Show the commit.
    if review_request_id is None:
        output = check_output([
            'git',
            '--no-pager',
            'log',
            creating_review_format,
            previous + '..' + sha])
        print '\nCreating diff of:'
        print output
    else:
        output = check_output([
            'git',
            '--no-pager',
            'log',
            updating_review_format,
            previous + '..' + sha])
        print '\nUpdating diff of:'
        print output

    # Show the "parent" commit(s).
    output = check_output([
        'git',
        '--no-pager',
        'log',
        parent_log_format,
        tracking_branch + '..' + previous])

    if output:
        print '\n... with parent diff created from:'
        print output

    if user_skipped_review():
        i = i + 1
        previous = sha
        parent_review_request_id = review_request_id
        continue

    # Strip the review url from the commit message, so that it is not included
    # in the summary message when GUESS_FIELDS is set in .reviewboardc. Update
    # the sha appropriately.
    if review_request_id:
        stripped_message = message[:pos]
        execute(['git', 'checkout', sha])
        execute(['git', 'commit', '--amend', '-m', stripped_message])
        sha = execute(['git', 'rev-parse', 'HEAD']).strip()
        execute(['git', 'checkout', branch])

    revision_range = previous + ':' + sha

    # Build the post-review/rbt command up to the point where they are common.
    command = post_review

    if args.tracking_branch is None:
        command = command + ['--tracking-branch=' + tracking_branch]

    if review_request_id:
        command = command + ['--review-request-id=' + review_request_id]

    # Determine how to specify the revision range.
    if rbt_executable in post_review and rbt_version >= LooseVersion('RBTools 0.6'):
       # rbt >= 0.6.1 supports '--depends-on' argument.
       # Only set the "depends on" if this is not the first review in the chain.
       if rbt_version >= LooseVersion('RBTools 0.6.1') and parent_review_request_id:
         command = command + ['--depends-on=' + parent_review_request_id]

       # rbt >= 0.6 revisions are passed in as args.
       command = command + sys.argv[1:] + [previous, sha]
    else:
        # post-review and rbt < 0.6 revisions are passed in using the revision
        # range option.
        command = command + \
            ['--revision-range=' + revision_range] + \
            sys.argv[1:]

    output = execute(command).strip()

    print output


    # If we already have a request_id, continue on to the next commit in the
    # chain. We update 'previous' from the shas[] array because we have
    # overwritten the temporary sha variable above.
    if review_request_id is not None:
        previous = shas[i]
        parent_review_request_id = review_request_id
        i = i + 1
        continue

    # Otherwise, get the request_id from the output of post-review, append it
    # to the commit message and rebase all other commits on top of it.
    lines = output.split('\n')

    # The last line of output in post-review is the review url.
    # The second to the last line of output in rbt is the review url.
    url = lines[len(lines) - 2] if 'rbt' in post_review \
        else lines[len(lines) - 1]

    # Using rbt >= 0.6.3 on Linux prints out two URLs where the second
    # one has /diff/ at the end. We want to remove this so that a
    # subsequent call to post-reviews does not fail when looking up
    # the reviewboard entry to edit.
    url = url.replace('diff/','')
    url = url.strip('/')
    review_request_id = os.path.basename(url)

    # Construct new commit message.
    message = message + '\n' + 'Review: ' + url + '\n'

    execute(['git', 'checkout', '-b', temporary_branch])
    execute(['git', 'reset', '--hard', sha])
    execute(['git', 'commit', '--amend', '-m', message])

    # Now rebase all remaining shas on top of this amended commit.
    j = i + 1
    old_sha = execute(['cat', os.path.join(git_dir, 'refs/heads', temporary_branch)]).strip()
    previous = old_sha
    while j < len(shas):
        execute(['git', 'checkout', shas[j]])
        execute(['git', 'rebase', temporary_branch])
        # Get the sha for our detached HEAD.
        new_sha = execute(['git', '--no-pager', 'log', '--pretty=format:%H', '-n', '1', 'HEAD']).strip()
        execute(['git',
                 'update-ref',
                 'refs/heads/' + temporary_branch,
                 new_sha,
                 old_sha])
        old_sha = new_sha
        shas[j] = new_sha
        j = j + 1

    # Okay, now update the actual branch to our temporary branch.
    new_sha = old_sha
    old_sha = execute(['cat', os.path.join(git_dir, 'refs/heads', branch)]).strip()
    execute(['git', 'update-ref', 'refs/heads/' + branch, new_sha, old_sha])

    i = i + 1
    parent_review_request_id = review_request_id
