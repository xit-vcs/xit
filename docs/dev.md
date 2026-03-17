This is a big project and I could use some help. That said, I am very picky about accepting changes.

* I usually prefer simple, dumb, compact solutions even if the more complex, verbose solution is more featureful or faster (though I'm open to the latter if the win is big enough).

* I'm suspicious of too much abstraction because it creates indirection in the codebase, which hurts readability, and can make it harder to make changes later.

* A little duplication is better than a bad abstraction!

This project is MIT licensed and there is no CLA or COC or any other acronymized hot mess.

The primary tests can be run with `zig build test`. This runs a few things worth knowing about:

* `src/test/main.zig`

  * This is a basic end-to-end test. Most actions are done through `main.run` which programmatically executes things via CLI args (in-process, not subprocessing). This helps to test that the CLI commands work correctly.

  * The work is done in a temp dir named `temp-test-main`.

  * The tests are run multiple times: once with the xit backend and once with the git backend. The git backend is also validated by running libgit2 functions at various points, to ensure that the git implementation is correct.

* `src/test/repo.zig`

  * A variety of tests that execute xit programmatically using the `Repo` struct. This is how xit is meant to be used as a library. Some of the more complicated stuff is tested here, like merging.

  * The tests are run in various temp dirs starting with `temp-test-repo-`.

  * Much like the main test, the repo tests are run both with the xit backend and the git backend.

Networking is tested with a separate command: `zig build testnet`

* The tests are separate because they rely on launching subprocesses. This makes them assume things about your system, and if they crash they may leave zombie processes on your machine, which is always fun.

* On Linux/Macos they assume that `git`, `ssh`, and `sshd` are on your PATH. On Windows, only `git` is assumed to be on your PATH.

* There are three networking actions tested: push, fetch, and clone. They create server and client repos in temp dirs starting with `temp-testnet-`. Each of these is run over each of the supported protocols:

  * `http` - Runs a server using the built-in HTTP server from the Zig standard library. This is run in-process using a separate thread. The server implements CGI by forwarding requests to `git http-backend` or `xit http-backend`, which it runs in a separate short-lived process. The client then communicates with it using the Zig's built-in HTTP client.

  * `raw` - Runs a server process using `git daemon` which the client communicates with over the raw git protocol.

    * This is currently disabled on Windows because spawning the process seems to block for some reason.

  * `ssh` - Runs a server process using `sshd` which the client communicates with by running an `ssh` process. The `sshd` server runs on a custom port and uses a custom config file, authorized keys file, etc. The `ssh` client uses a custom config, known hosts file, etc. Both use custom keys. This way, they should run consistently and not interfere with whatever is on your system.

    * This is currently disabled on Windows because sshd isn't normally available on it, and some stuff will need to be changed to get it to work even if it is there.

  * `file` - Runs the action over the local filesystem without any networking or server involved. This is important so we can support local remotes.

* As I said, unclean failures can lead to zombie processes, particularly the `git daemon` process from the `raw` tests. They can prevent the tests from succeeding afterwards. On Linux I search for them with `ps aux | grep git` and kill them mercilessly and with prejudice.

Additionally, both `test` and `testnet` support test case filtering by `-Dtest-filter=` option.

The UI can be tested with `zig build try`.

* It creates a temp dir called `temp-try` and copies the entire `.git` dir (from the repo it is running in) into this temp dir. It then initializes a xit repo (with a `.xit` dir) in this temp dir. Next, it checks out out several recent commits into this dir and commits them into the newly-formed xit repo. This creates a nice test repo seeded with real content.

* After the test repo in `temp-try` is finished being built, this command runs the TUI. You should see the commits it made in the `log` section, and in the `status` section you should see various uncommitted changes that were intentionally made.

I don't have great benchmarks right now, but here's the ghetto way I do it:

* `zig build && time ./zig-out/bin/try --cli --patch`

* This command builds everything and then runs the above-mentioned `try` command, but this time with a few flags. The `--cli` flag prevents the TUI from launching, because a benchmark wouldn't be very useful if it never finished. The `--patch` flag makes it generate patches for each commit.

* Since the `try` command creates several commits, adding the `--patch` flag will make it generate a bunch of patches, so it is a convenient way to get a quick benchmark when making changes to the myers diff code or whatever.
