npm run testcase "#bulletproof" | grep -P "{\"Comms" > /home/anhnt/projects/go/src/github.com/tomochain/tomochain/core/vm/privacy/bulletproof.json ;
cd /home/anhnt/projects/go/src/github.com/tomochain/tomochain/core/vm/privacy &&  go test -timeout 30s github.com/tomochain/tomochain/core/vm/privacy -run '^(TestMRPProveFromJS)$' -v
