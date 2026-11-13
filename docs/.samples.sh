node dist/src/cli.js examples/phish-invoice.eml > /tmp/a.md; diff /tmp/a.md docs/sample-phish.md
node dist/src/cli.js examples/bec-ceo.eml > /tmp/b.md; diff /tmp/b.md docs/sample-bec.md
node dist/src/cli.js examples > /tmp/c.md; diff /tmp/c.md docs/sample-batch.md
test "$(node dist/src/cli.js examples --fail-on phishing >/dev/null; echo $?)" = "1"
