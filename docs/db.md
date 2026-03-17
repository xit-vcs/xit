The fact that git doesn't have a "real database" is both its greatest strength and greatest weakness. Linus even called out monotone's use of a "real database" (SQLite) in his famous [YOU are full of bullshit](https://harmful.cat-v.org/software/c++/linus) rant:

> If you want a VCS that is written in C++, go play with Monotone. Really. They use a "real database". They use "nice object-oriented libraries". They use "nice C++ abstractions". And quite frankly, as a result of all these design decisions that sound so appealing to some CS people, the end result is a horrible and unmaintainable mess.

Linus' disdain for overuse of abstraction has aged pretty well, I'd say. C++ became a kitchen sink language full of language features (with Rust sadly following its lead), and I can't think of a single codebase in it that I admire. Meanwhile, an old C codebase like [Lua](https://github.com/lua/lua) is striking in how flat, simple, stupid, and clean it is. It should be no mystery why I like Zig.

That being said, we really have to unpack this topic about a "real database". What is a real database? What does git have instead? What are its upsides and downsides compared to what monotone had? What does xit have? Why am I asking so many goddamn questions?

In a way, git's database is the filesystem. Inside the `.git` directory is a number of completely separate files that collectively record the state of your git repo.

* `.git/HEAD` has the object id or ref that is currently checked out

* `.git/index` has the list of files that are staged

* `.git/refs/` has all the refs

* ...and much more

The bad

* Since they are separate files, updating them isn't atomic. If, for example, we need to update what object id a ref points to *and* update `HEAD` to point to the ref, these must be done separately and an error halfway through will not rollback the change to the ref. A "real database" generally provides some concept of a transaction for this purpose.

* But for me, the bigger problem is that git's data structures are just not that great. The core data structure it maintains is the tree of commits starting at a given ref. In simple cases it is essentially a linked list, and much like the linked lists you may have used, it can't efficiently look up an item by index. Want to view the first commit? Keep following the parent commits until you find one with no parent. Want to find the descendent(s) of a commit? Uhhh...well, you can't.

  * Some limitations git's basic data structures have been alleviated by adding "yet another file" somewhere in the .git dir that organizes it differently. The `commit-graph` makes it faster to traverse commit history. The `reftable` stores refs in an efficient binary format. The fact that git keeps adding these special-cased solutions reveals the problem: it doesn't have access to a general purpose database, and each one adds more complexity to git's previously-simple on-disk format.

* In any system, you can get really far with just two data structures: an associative collection (a hashmap) and a sequential collection (an arraylist). Git doesn't have either in a general sense. Its object store is technically a kind of hashmap, but it is specialized to one use. Git can't just store arbitrary key-value pairs in there. If you had a database that could represent those two data structures and nest them as needed, you could model almost anything.

* Without a more general set of data structures, there are a variety of features that are just not practical to implement in git. [Patch-based merging](patch.md) will probably never exist in git because it requires a lot of extra data that git simply can't efficiently track. The value of a "real database" is that new features like this are practical because it provides a general set of tools to organize data. Git's mishmash of ad hoc file formats locks its feature set in and makes new features a big engineering effort.

The good

* It's easy to pretentiously chide git for not having a "real database", but git's design has one benefit that nobody ever talks about: it can be *reimplemented*. There are multiple independent implementations of git in different languages (I would know...xit has its own git implementation written in Zig). People don't appreciate the timeless beauty of a system that is simple enough to be reimplemented from scratch.

* SQLite is a very powerful database, but it is not a small dependency. It is tens of thousands of lines of C. If a VCS uses it, it effectively cannot be reimplemented from scratch; all other implementations will need to bring it in as a dependency unless they want to spend years reimplementing SQLite too.

* The only way a technology can ensure its own longevity is to find a way to outlive its initial implementation. Git's repo format is simple enough to do this, but VCSes that use a "real database" typically aren't. If only there was a way to have our cake and eat it too: To have a powerful, transactional database that was small and simple enough to be reimplemented.

The xit

* The heart of xit is [xitdb](https://github.com/xit-vcs/xitdb), an immutable database that it uses for all its data (besides the objects themselves, such as files, which are stored as separate [chunks](chunk.md)). The database stores everything in a single file located at `.xit/db`.

* xitdb has all the trappings of a "real" database, including atomicity: the database will never be left in an inconsistent state if a transaction fails. More importantly, it has general-purpose data structures (a hashmap and an arraylist) that can be nested arbitrarily.

* Unlike SQLite, xitdb is immutable. Each transaction creates a new "copy" of the database, and it shares data with previous copies. Copying immutable data is just a pointer copy. This means xit can store commit state very efficiently: just copy the pointer to the last commit's state, and all changes to it won't affect the last commit. This also allows xit to undo any transaction, called "universal undo".

* The best feature of xitdb, though, is that it is around 3000 lines of Zig with no external dependencies. Compared to a project like SQLite, xitdb is more than an order of magnitude smaller. This brings it well into the territory of being reimplementable. Rewriting it in a different language is entirely doable. In fact, I've already done so: [xitdb-java](https://github.com/xit-vcs/xitdb-java), [xitdb-ts](https://github.com/xit-vcs/xitdb-ts), and [xitdb-go](https://github.com/xit-vcs/xitdb-go) are compatible reimplementations of the database.

* In this way, xit tries to get the best of both worlds. It retains the simplicity of git's repo format, while having the power of a "real database". The benefit of having general-purpose data structures, rather than the specialized, hard-coded data structures in git, can't be overstated. New features that require new data to be stored are not a massive engineering effort to create. This is a gift that will keep on giving.
