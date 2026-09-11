const std = @import("std");
const builtin = @import("builtin");
const xit = @import("xit");
const rp = xit.repo;

test "sign commit and tag" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    if (.windows != builtin.os.tag) {
        try testSign(.sha1, io, allocator);
        try testSign(.sha256, io, allocator);
    }
}

fn testSign(
    comptime hash_kind: xit.hash.HashKind,
    io: std.Io,
    allocator: std.mem.Allocator,
) !void {

    // create the temp dir
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const temp_path = try temp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(temp_path);

    var repo = try rp.Repo(.git, .{ .is_test = true, .hash = hash_kind }).init(io, allocator, .{ .path = temp_path });
    defer repo.deinit(io, allocator);

    // create priv key
    const priv_key_file = try temp.dir.createFile(io, "key", .{});
    defer priv_key_file.close(io);
    try priv_key_file.writeStreamingAll(io,
        \\-----BEGIN OPENSSH PRIVATE KEY-----
        \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        \\QyNTUxOQAAACCniLPJiaooAWecvOCeAjoJwCSeWxzysvpTNkpYjF22JgAAAJA+7hikPu4Y
        \\pAAAAAtzc2gtZWQyNTUxOQAAACCniLPJiaooAWecvOCeAjoJwCSeWxzysvpTNkpYjF22Jg
        \\AAAEDVlopOMnKt/7by/IA8VZvQXUS/O6VLkixOqnnahUdPCKeIs8mJqigBZ5y84J4COgnA
        \\JJ5bHPKy+lM2SliMXbYmAAAAC3JhZGFyQHJvYXJrAQI=
        \\-----END OPENSSH PRIVATE KEY-----
        \\
    );
    if (.windows != builtin.os.tag) {
        try priv_key_file.setPermissions(io, @enumFromInt(0o600));
    }

    // create pub key
    const pub_key_path = try std.fs.path.join(allocator, &.{ temp_path, "key.pub" });
    defer allocator.free(pub_key_path);
    const pub_key_file = try temp.dir.createFile(io, "key.pub", .{});
    defer pub_key_file.close(io);
    const pub_key =
        \\ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKeIs8mJqigBZ5y84J4COgnAJJ5bHPKy+lM2SliMXbYm radar@roark
        \\
    ;
    try pub_key_file.writeStreamingAll(io, pub_key);
    if (.windows != builtin.os.tag) {
        try pub_key_file.setPermissions(io, @enumFromInt(0o600));
    }

    // add key to config and turn signing on
    try repo.addConfig(io, allocator, .{ .name = "user.signingkey", .value = pub_key_path });
    try repo.addConfig(io, allocator, .{ .name = "gpg.format", .value = "ssh" });
    try repo.addConfig(io, allocator, .{ .name = "commit.gpgsign", .value = "true" });
    try repo.addConfig(io, allocator, .{ .name = "tag.gpgsign", .value = "true" });

    // make a commit
    const hello_txt = try repo.core.work_dir.createFile(io, "hello.txt", .{ .truncate = true });
    defer hello_txt.close(io);
    try hello_txt.writeStreamingAll(io, "hello, world!");
    try repo.add(io, allocator, &.{"hello.txt"});
    const commit_oid = try repo.commit(io, allocator, .{ .message = "let there be light" });

    // add a tag
    const tag_oid = try repo.addTag(io, allocator, .{ .name = "1.0.0", .message = "hi" });

    // verify the signatures with git
    try temp.dir.writeFile(io, .{ .sub_path = "allowed_signers", .data = "radar@roark " ++ pub_key });
    for ([_][]const u8{ "verify-commit", "verify-tag" }, [_][]const u8{ &commit_oid, &tag_oid }) |command, oid| {
        const result = try std.process.run(allocator, io, .{
            .argv = &.{ "git", "-c", "gpg.ssh.allowedSignersFile=allowed_signers", command, oid },
            .cwd = .{ .path = temp_path },
        });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        if (result.term != .exited or result.term.exited != 0) {
            std.debug.print("git {s}: {s}", .{ command, result.stderr });
            return error.GitCommandFailed;
        }
    }
}
