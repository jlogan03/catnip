# Check whether this branch's changes need to be a major, minor, or patch

branch_name=$(git symbolic-ref --short HEAD)

git checkout main
cargo +nightly rustdoc -- -Zunstable-options --output-format json
mkdir tmp
cp ./target/doc/catnip.json ./tmp/catnip-main.json

git checkout $branch_name
cargo +nightly rustdoc -- -Zunstable-options --output-format json
cp ./target/doc/catnip.json ./tmp

cargo semver-checks diff-files --current ./tmp/catnip.json --baseline ./tmp/catnip-main.json

rm -rf ./tmp