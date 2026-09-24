# fish completion for pinned.
#
# Static on purpose: nothing here runs pinned or reads its record tree, so
# completing a word never touches /var/db/pinned and never asks for sudo.
# Actions, flags and fixed value sets mirror the script's argument parsers
# and man pinned; keep them in step when a verb or flag changes.

# The action is always the first word (the script reads it from $1), so the
# conditions below index the command line instead of scanning it for a
# subcommand name that could also be a path.
function __pinned_needs_action
    test (count (commandline -opc)) -eq 1
end

function __pinned_action_is # action...
    set -l words (commandline -opc)
    test (count $words) -ge 2; and contains -- $words[2] $argv
end

# signer and ignorable take a sub-verb as their second word.
function __pinned_needs_sub # action
    set -l words (commandline -opc)
    test (count $words) -eq 2; and test "$words[2]" = "$argv[1]"
end

function __pinned_sub_is # action sub...
    set -l words (commandline -opc)
    test (count $words) -ge 3; and test "$words[2]" = "$argv[1]"
    and contains -- $words[3] $argv[2..-1]
end

# How many words precede the cursor, the command included.
function __pinned_argc_is # n
    test (count (commandline -opc)) -eq $argv[1]
end

set -l algos 'sha256 sha384 sha512 blake2b-256 blake2b-384 blake2b-512 blake3'

complete -c pinned -f

# --- actions ------------------------------------------------------------------
complete -c pinned -n __pinned_needs_action -l version -d 'Print the release version'
complete -c pinned -n __pinned_needs_action -a review -d '(sudo) Review the diff since the last pin, write pin'
complete -c pinned -n __pinned_needs_action -a tombstone -d '(sudo) Retire a pinned file that is gone'
complete -c pinned -n __pinned_needs_action -a rekey -d '(sudo) Re-key a record to a moved path'
complete -c pinned -n __pinned_needs_action -a declare -d '(sudo) Declare the release name a deployer syncs ref= to'
complete -c pinned -n __pinned_needs_action -a verify -d 'File-pin verdict, exit-code contract for gates'
complete -c pinned -n __pinned_needs_action -a cat -d 'The approved bytes, from root custody'
complete -c pinned -n __pinned_needs_action -a rev -d 'The pinned rev or the declared release name'
complete -c pinned -n __pinned_needs_action -a sign -d 'Create a signed tag at the pinned hash'
complete -c pinned -n __pinned_needs_action -a signer -d 'Allowed-signers ceremonies and lookups'
complete -c pinned -n __pinned_needs_action -a ignorable -d 'Ignorable-JSON-key grants'
complete -c pinned -n __pinned_needs_action -a status -d 'Record vs live state'
complete -c pinned -n __pinned_needs_action -a show -d 'Trusted re-display, records nothing'
complete -c pinned -n __pinned_needs_action -a list -d 'Live pins in your tier'
complete -c pinned -n __pinned_needs_action -a slot -d 'Print the slot directory for a path'
complete -c pinned -n __pinned_needs_action -a setup -d '(sudo) Provision sudoers digest pin, self-install'

# --- review -------------------------------------------------------------------
complete -c pinned -n '__pinned_action_is review' -a '(__fish_complete_directories)'
complete -c pinned -n '__pinned_action_is review' -l tag -x -d 'Review and pin this tag'\''s commit, not HEAD'
complete -c pinned -n '__pinned_action_is review' -l signed-tag -x -d 'Tag that must verify against allowed signers (repeatable)'
complete -c pinned -n '__pinned_action_is review' -l trust -d 'Skip a first approval'\''s full-tree review, loudly'
complete -c pinned -n '__pinned_action_is review' -l step -d 'Walk the commits since the pin one at a time'
complete -c pinned -n '__pinned_action_is review' -l messages -d 'Print each commit message whole in the listing'
complete -c pinned -n '__pinned_action_is review' -l backward -d 'Declare the candidate an ancestor of the pin'
complete -c pinned -n '__pinned_action_is review' -l diverged -d 'Declare the candidate off the pinned line'
complete -c pinned -n '__pinned_action_is review' -l file -r -F -d 'File-pin ceremony for this path (repeatable)'
complete -c pinned -n '__pinned_action_is review' -l baseline -r -F -d 'Copy of the prior approved bytes for the preceding --file'
complete -c pinned -n '__pinned_action_is review' -l baseline-store -x -a '(__fish_complete_directories)' -d 'Directory of stored witnesses'
complete -c pinned -n '__pinned_action_is review' -l ignore-json-key -x -d 'Dotted JSON key the preceding --file may drift'
complete -c pinned -n '__pinned_action_is review' -l algo -x -a "$algos" -d 'Hash algorithm for file pins'
complete -c pinned -n '__pinned_action_is review' -l store -d 'Keep the approved bytes in root custody'
complete -c pinned -n '__pinned_action_is review' -l yes -d 'Skip the pre-sudo gate'

# --- tombstone, rekey, setup --------------------------------------------------
complete -c pinned -n '__pinned_action_is tombstone rekey' -F
complete -c pinned -n '__pinned_action_is tombstone rekey' -l yes -d 'Skip the pre-sudo gate'
complete -c pinned -n '__pinned_action_is setup' -l yes -d 'Skip the setup confirmation'

# --- declare ------------------------------------------------------------------
complete -c pinned -n '__pinned_action_is declare' -a '(__fish_complete_directories)'
complete -c pinned -n '__pinned_action_is declare' -l release -x -d 'Release name to declare'
complete -c pinned -n '__pinned_action_is declare' -l no-release -d 'Clear the declared release name'
complete -c pinned -n '__pinned_action_is declare' -l yes -d 'Skip the pre-sudo gate'

# --- verify, cat, status, show, slot ------------------------------------------
complete -c pinned -n '__pinned_action_is verify cat status show slot' -F
complete -c pinned -n '__pinned_action_is verify' -l emit -d 'Print the verified bytes on stdout'
complete -c pinned -n '__pinned_action_is verify' -l frozen -r -F -d 'Verify this caller-frozen copy against the record'
complete -c pinned -n '__pinned_action_is verify' -l baseline -r -F -d 'Your own witness for the ignored-key comparison'
complete -c pinned -n '__pinned_action_is show' -s a -l algo -x -a "$algos" -d 'Hash algorithm'
complete -c pinned -n '__pinned_action_is show' -s l -l length -x -d 'Output length in bits (blake3 only)'

# --- rev, sign ----------------------------------------------------------------
complete -c pinned -n '__pinned_action_is rev' -a '(__fish_complete_directories)'
complete -c pinned -n '__pinned_action_is rev' -l release -d 'Print the declared release name instead'
complete -c pinned -n '__pinned_action_is sign; and __pinned_argc_is 2' -a '(__fish_complete_directories)'

# --- signer -------------------------------------------------------------------
complete -c pinned -n '__pinned_needs_sub signer' -a add -d '(sudo) Record a key'
complete -c pinned -n '__pinned_needs_sub signer' -a remove -d '(sudo) Remove a key'
complete -c pinned -n '__pinned_needs_sub signer' -a list -d 'Principals, key types, fingerprints'
complete -c pinned -n '__pinned_needs_sub signer' -a path -d 'The allowed-signers file a signed tag verifies against'
complete -c pinned -n '__pinned_sub_is signer add remove list path' -l repo -x -a '(__fish_complete_directories)' -d 'Target the per-repo override'
complete -c pinned -n '__pinned_sub_is signer add remove' -l file -r -F -d 'Public key file'
complete -c pinned -n '__pinned_sub_is signer add remove' -l key -x -d 'Public key line'
complete -c pinned -n '__pinned_sub_is signer add' -l principal -x -d 'Identity signature verification matches'
complete -c pinned -n '__pinned_sub_is signer add remove' -l yes -d 'Skip the pre-sudo gate'

# --- ignorable ----------------------------------------------------------------
complete -c pinned -n '__pinned_needs_sub ignorable' -a add -d '(sudo) Grant a dotted JSON key'
complete -c pinned -n '__pinned_needs_sub ignorable' -a remove -d '(sudo) Withdraw a grant'
complete -c pinned -n '__pinned_needs_sub ignorable' -a list -d 'Machine, user and effective tiers'
complete -c pinned -n '__pinned_sub_is ignorable add remove' -l under -x -a '(__fish_complete_directories)' -d 'Scope the grant to this subtree'
complete -c pinned -n '__pinned_sub_is ignorable add remove' -l yes -d 'Skip the pre-sudo gate'

# --- list ---------------------------------------------------------------------
complete -c pinned -n '__pinned_action_is list' -l under -x -a '(__fish_complete_directories)' -d 'Only pins under this directory'
