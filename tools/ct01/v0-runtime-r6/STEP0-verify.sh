# STEP 0 — NON-ROOT, OFFLINE. Source it, then: ct01_v0rt_step0 . Reads files only: no docker, no sudo, no network. rc 0 is NOT permission to run.
ct01_v0rt_step0() {
    local P=/home/dathq/projects/ct01-v0-runtime-r6 rc t
    ( cd "$P" && /usr/bin/sha256sum --strict --check --quiet SHA256SUMS ) || { echo "STOP: tree differs from its manifest"; return 11; }
    /usr/bin/bash -n "$P/run-v0-runtime.sh" || { echo "STOP: runner syntax"; return 12; }
    /usr/bin/python3 -I -B -c "import ast,sys;[ast.parse(open(f).read()) for f in sys.argv[1:]]" "$P/evaluate_v0_runtime.py" "$P/verify_pins.py" "$P/make_pins.py" "$P/make_entry.py" "$P/verify_export.py" "$P/build_f6_guest.py" || return 13
    t=$(mktemp -d /tmp/ct01-v0rt-step0.XXXXXX) || return 15
    mkdir -p "$t/tree" "$t/inputs" && cp -a "$P"/. "$t/tree/" || return 15
    /usr/bin/python3 -I -B -c "
import json,shutil,pathlib,sys
t=pathlib.Path(sys.argv[1]); pins=json.load(open(t/'tree/pins.json'))
for m in pins['sources'].values():
    d=t/m['path']; d.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(m['src'],d)
" "$t" || return 15
    /usr/bin/python3 -I -B "$t/tree/verify_pins.py" "$t" || { echo "STOP: pins/inputs differ"; rm -rf "$t"; return 14; }
    rm -rf "$t"
    [ ! -e "$P/run" ] || { echo "STOP: $P/run exists"; return 16; }
    echo "manifest sha256: $(/usr/bin/sha256sum -- "$P/SHA256SUMS" | cut -d' ' -f1)"
    echo "root command: $P/root-command.txt (review it; the assistant does not run it)"
    echo "OK: files as reviewed. NOT permission to run (needs the user's decision: sudo/Docker, see RUNBOOK.md)."
    return 0
}
