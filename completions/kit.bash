# kit(1) bash completion
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Install:
#   cp kit.bash /usr/local/etc/bash_completion.d/    (macOS / Homebrew)
#   cp kit.bash /etc/bash_completion.d/              (most Linux)
# or `source kit.bash` from your ~/.bashrc.
#
# Argument names come from the private, local-only kit __complete helper.

_kit_complete() {
    local cur prev words cword
    _init_completion || return 0

    if [[ $cword -gt 1 && $cur != -* ]]; then
        local names
        names=$(kit __complete "${words[@]:1:$((cword - 1))}" 2>/dev/null)
        if [[ -n $names ]]; then
            if [[ $cword -eq 2 && ( ${words[1]} == switch || ${words[1]} == checkout ) ]]; then
                names+=$'\n-\n@{-1}'
            fi
            COMPREPLY=( $(compgen -W "$names" -- "$cur") )
            return 0
        fi
    fi

    local subcommands="init add rm mv restore reset hash cat cat-file show tree ls-tree ls-files rev-parse rev-list merge-base show-ref for-each-ref symbolic-ref update-ref ref commit log reflog status diff branch checkout switch clean tag config merge push pull fetch stash clone remote key grant epoch visibility keygen cherry-pick revert rebase bisect gc worktree sparse-checkout serve mcp git blame prove verify verify-proof closure attest verify-attest self version help"
    # Top-level flags. --version/-V are aliases of the `version` subcommand.
    local top_flags="--help -h --version -V"

    # First non-flag word is the subcommand.
    if [[ $cword -eq 1 ]]; then
        if [[ $cur == -* ]]; then
            COMPREPLY=( $(compgen -W "$top_flags" -- "$cur") )
        else
            COMPREPLY=( $(compgen -W "$subcommands" -- "$cur") )
        fi
        return 0
    fi

    # Per-subcommand suggestions. Intentionally minimal — we only
    # surface the --help / --version / well-documented flags so shell
    # users get tab-completion for the common fast-path.
    case "${words[1]}" in
        init)
            COMPREPLY=( $(compgen -W "-q --quiet --help" -- "$cur") )
            ;;
        add)
            COMPREPLY=( $(compgen -W "-A --all -u --update -f --force -n --dry-run -p --patch --help" -- "$cur") )
            ;;
        rm)
            COMPREPLY=( $(compgen -W "--cached -r --recursive -f --force --help" -- "$cur") )
            ;;
        mv)
            COMPREPLY=( $(compgen -W "-f --force --help" -- "$cur") )
            ;;
        restore)
            COMPREPLY=( $(compgen -W "--staged --worktree --source -f --force --help" -- "$cur") )
            ;;
        reset)
            COMPREPLY=( $(compgen -W "--soft --mixed --hard -f --force -q --quiet --help" -- "$cur") )
            ;;
        clean)
            COMPREPLY=( $(compgen -W "-n --dry-run -f --force -d -x -X --help" -- "$cur") )
            ;;
        diff)
            COMPREPLY=( $(compgen -W "--staged --cached --name-only --name-status --stat --merge-base --exit-code --quiet --color --no-color -w --ignore-all-space -b --ignore-space-change -U --unified -z --help" -- "$cur") )
            ;;
        cat-file)
            COMPREPLY=( $(compgen -W "-t -s -p --batch --help" -- "$cur") )
            ;;
        ls-tree)
            COMPREPLY=( $(compgen -W "-r -z --help" -- "$cur") )
            ;;
        ls-files)
            COMPREPLY=( $(compgen -W "-s --stage -z --others --ignored --exclude-standard --help" -- "$cur") )
            ;;
        rev-parse)
            COMPREPLY=( $(compgen -W "--short --abbrev-ref --show-toplevel --verify -q --quiet --help" -- "$cur") )
            ;;
        show-ref)
            COMPREPLY=( $(compgen -W "--heads --tags --help" -- "$cur") )
            ;;
        for-each-ref)
            COMPREPLY=( $(compgen -W "--format --help" -- "$cur") )
            ;;
        symbolic-ref)
            COMPREPLY=( $(compgen -W "--short --help" -- "$cur") )
            ;;
        update-ref)
            COMPREPLY=( $(compgen -W "-d --delete --help" -- "$cur") )
            ;;
        ref)
            COMPREPLY=( $(compgen -W "list cat --pattern --help" -- "$cur") )
            ;;
        status)
            COMPREPLY=( $(compgen -W "--porcelain -s --short -z --help" -- "$cur") )
            ;;
        commit)
            COMPREPLY=( $(compgen -W "-a --all --allow-empty --amend -m --message -F --file --author -q --quiet --help" -- "$cur") )
            ;;
        blame)
            COMPREPLY=( $(compgen -W "--format -L --lines -w --ignore-whitespace -M --find-moves -C --find-copies --ignore-rev --ignore-revs-file --ignore-rev-precise --first-parent --reverse --help" -- "$cur") )
            ;;
        log)
            COMPREPLY=( $(compgen -W "--oneline --abbrev-commit --abbrev --format --author --grep --since --until --no-merges --first-parent -p --patch --stat --decorate --graph --all -n --help" -- "$cur") )
            ;;
        reflog)
            COMPREPLY=( $(compgen -W "--format -n --help" -- "$cur") )
            ;;
        pull)
            COMPREPLY=( $(compgen -W "--all --rebase --no-ff --tags --no-tags --no-verify-signatures --format -q --quiet --help" -- "$cur") )
            ;;
        fetch)
            COMPREPLY=( $(compgen -W "--all -p --prune --tags --no-tags --no-verify-signatures --format -q --quiet --help" -- "$cur") )
            ;;
        push)
            COMPREPLY=( $(compgen -W "--all --tags --delete -f --force --force-with-lease -u --set-upstream --dry-run --help" -- "$cur") )
            ;;
        clone)
            COMPREPLY=( $(compgen -W "--sparse --tags --no-tags --help" -- "$cur") )
            ;;
        branch)
            COMPREPLY=( $(compgen -W "-v --verbose -d -D -m -u --set-upstream-to --unset-upstream -r --remotes -a --all --list --contains --no-contains --merged --no-merged --show-current --format --help" -- "$cur") )
            ;;
        show)
            COMPREPLY=( $(compgen -W "--stat --help" -- "$cur") )
            ;;
        merge)
            COMPREPLY=( $(compgen -W "--continue --abort --no-commit -m --message --help" -- "$cur") )
            ;;
        cherry-pick)
            COMPREPLY=( $(compgen -W "--continue --abort -n --no-commit -m --mainline --help" -- "$cur") )
            ;;
        tag)
            COMPREPLY=( $(compgen -W "-a --annotate -s --sign -m --message -d --delete -l --list --author --help" -- "$cur") )
            ;;
        rebase)
            COMPREPLY=( $(compgen -W "-i --interactive --onto --continue --skip --abort --help" -- "$cur") )
            ;;
        revert)
            COMPREPLY=( $(compgen -W "--continue --abort -n --no-commit -m --mainline --format --help" -- "$cur") )
            ;;
        bisect)
            COMPREPLY=( $(compgen -W "start good bad reset" -- "$cur") )
            ;;
        self)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "update" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "--version --check --allow-downgrade --format --help" -- "$cur") )
            fi
            ;;
        gc)
            COMPREPLY=( $(compgen -W "-n --dry-run --grace-secs --help" -- "$cur") )
            ;;
        worktree)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "add list remove prune move lock unlock repair --help" -- "$cur") )
            else
                case "${words[2]}" in
                    list)
                        COMPREPLY=( $(compgen -W "--porcelain --help" -- "$cur") )
                        ;;
                    remove|move)
                        COMPREPLY=( $(compgen -W "-f --force --help" -- "$cur") )
                        ;;
                    prune)
                        COMPREPLY=( $(compgen -W "--dry-run --help" -- "$cur") )
                        ;;
                    lock)
                        COMPREPLY=( $(compgen -W "--reason --help" -- "$cur") )
                        ;;
                    *)
                        COMPREPLY=( $(compgen -W "--help" -- "$cur") )
                        ;;
                esac
            fi
            ;;
        stash)
            COMPREPLY=( $(compgen -W "save push list pop apply drop clear show -u --include-untracked -m --message" -- "$cur") )
            ;;
        remote)
            COMPREPLY=( $(compgen -W "add set remove rename get-url set-url -v --verbose --help" -- "$cur") )
            ;;
        key)
            COMPREPLY=( $(compgen -W "generate list import export delete --help" -- "$cur") )
            ;;
        git)
            COMPREPLY=( $(compgen -W "export import fetch pull verify status format-patch --remote-name --ref --no-attest --algorithm --signer --key --json --passthrough --fork-audit --stdout -o --output-directory --help" -- "$cur") )
            ;;
        prove)
            COMPREPLY=( $(compgen -W "--chunk --range -o --output --format --help" -- "$cur") )
            ;;
        verify-proof)
            COMPREPLY=( $(compgen -W "--expect-path --trusted --trust-roots --format --payload-out --help" -- "$cur") )
            ;;
        closure)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "export verify" -- "$cur") )
            else
                case "${words[2]}" in
                    export)
                        COMPREPLY=( $(compgen -W "--history -o --output --force --format --help" -- "$cur") )
                        ;;
                    verify)
                        COMPREPLY=( $(compgen -W "--from --history --show-unreferenced --format --help" -- "$cur") )
                        ;;
                    *)
                        COMPREPLY=( $(compgen -W "export verify --help" -- "$cur") )
                        ;;
                esac
            fi
            ;;
        grant)
            COMPREPLY=( $(compgen -W "create add list revoke --cap --grantee --repo --all --refs --audience --ttl --epoch --offline --remote --store --namespace --scheme --print-statement --statement-file --signature --webauthn-assertion --check --json --prune --timeout --help" -- "$cur") )
            ;;
        epoch)
            COMPREPLY=( $(compgen -W "show bump --by --namespace --audience --timeout --json --scheme --print-statement --statement-file --signature --webauthn-assertion --help" -- "$cur") )
            ;;
        visibility)
            COMPREPLY=( $(compgen -W "set public private --statement --audience --timeout --scheme --print-statement --statement-file --signature --webauthn-assertion --help" -- "$cur") )
            ;;
        keygen)
            COMPREPLY=( $(compgen -W "--algorithm --force --print-pubkey --help" -- "$cur") )
            ;;
        attest)
            COMPREPLY=( $(compgen -W "--commit --algorithm --signer --predicate-type --predicate-file --additional-signer --external-signer-arg --help" -- "$cur") )
            ;;
        verify-attest)
            COMPREPLY=( $(compgen -W "--commit --trust-roots --algorithm --help" -- "$cur") )
            ;;
        switch)
            COMPREPLY=( $(compgen -W "-c -C - @{-1} --help" -- "$cur") )
            ;;
        checkout)
            COMPREPLY=( $(compgen -W "-b -B -f --force - @{-1} --help" -- "$cur") )
            ;;
        merge-base)
            COMPREPLY=( $(compgen -W "--is-ancestor --help" -- "$cur") )
            ;;
        rev-list)
            COMPREPLY=( $(compgen -W "--count -n --max-count --help" -- "$cur") )
            ;;
        *)
            COMPREPLY=( $(compgen -W "--help" -- "$cur") )
            ;;
    esac
}

complete -F _kit_complete kit
