With xit, I have a pretty ambitious goal: it will use *no third party libraries at all*. We're playing it on hard mode, baby! Moreover, xit can be easily used as a library itself, and it includes a pure Zig implementation of git, so you can use it to interact with xit *and* git repos.

No third-party libraries

* One of the most soul-sucking aspects of modern software development is running a build command and watching in horror as hundreds of transitive dependencies are downloaded. We are facing a crisis in software complexity, and many people don't even see it as a problem.

* The only dependencies of xit are a few Zig libraries I wrote myself, as well as the Zig standard library. The copy of libgit2 in this repo is only used by tests to validate xit's git implementation. In prod, xit is a pure Zig program.

* Writing things from scratch can lead to a much simpler codebase and dramatically improve the ability to add features and fix problems:

  * Of course, libraries are not always bad, but people over-rely on them, either due to insecurity ("I couldn't write that") or a misplaced fear of "reinventing the wheel". If you're the former case, then that is more reason to write things from scratch, because that's how you get better! If you're the latter case, then consider the possibility that all good software hasn't already been invented.

  * When you use a library, you usually only need a fraction of its functionality. To replace it with from-scratch code, you only need to implement the parts you need. And since you aren't making it for general use, you have the benefit of specializing the code. General purpose libraries need to add a lot of abstractions that you can avoid in your from-scratch implementation.

  * When people rely on a ton of libraries, they fool themselves into thinking their codebase is simple because they don't see the code contained in those libraries. It's like when a child covers his head with a blanket because of the monster under his bed, comforting himself by saying "if I can't see it, it can't hurt me". Complexity exists whether you see it directly or not.

  * Third-party libraries tend to accelerate you early on, but can slow you down in the long run. By writing more things from scratch, you are more empowered to fix problems, because you understand the code and you can change it directly rather than by forking a library.

Using xit as a library

* While xit doesn't pull in third-party libraries, you can and should use xit as a library in your Zig projects. Even if you don't care about xit as a version control system, you can use its git implementation to programmatically read and write to git repos. Think of it as a modern, pure-Zig alternative to libgit2.

* After adding xit as a library with the Zig build system, you'll be able to use it programmatically through the `Repo` struct. I made [a starter project](https://github.com/xit-vcs/xitstarter) showing how to do this:

```zig
const std = @import("std");
const xit = @import("xit");
const rp = xit.repo;

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    const cwd_path = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd_path);

    const work_path = try std.fs.path.resolve(allocator, &.{ cwd_path, "myrepo" });
    defer allocator.free(work_path);

    var repo = try rp.Repo(.xit, .{}).init(io, allocator, .{ .path = work_path });
    defer repo.deinit(io, allocator);

    try repo.addConfig(io, allocator, .{ .name = "user.name", .value = "mr magoo" });
    try repo.addConfig(io, allocator, .{ .name = "user.email", .value = "mister@magoo" });

    const readme = try repo.core.work_dir.createFile(io, "README.md", .{});
    defer readme.close(io);
    try readme.writeStreamingAll(io, "hello, world!");
    try repo.add(io, allocator, &.{"README.md"});

    const oid = try repo.commit(io, allocator, .{ .message = "initial commit" });
    std.debug.print("committed with object id: {s}\n", .{oid});
}
```

* If you want to create a git repo instead of a xit repo, only a single character needs to be changed in the code above: from `rp.Repo(.xit, .{})` to `rp.Repo(.git, .{})`. The `Repo` struct works the same regardless of which "backend" you choose to use.

* There is a lot more functionality available through this struct, but like any new open source project I'm moving too quickly to bother with proper documentation. For the adventurous, just read `src/repo.zig` in the xit source code to learn what you can do.
