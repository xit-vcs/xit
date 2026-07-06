Handling large, binary files well is non-negotiable for the next version control system. People are using VCSes for more things than in the past, and many of those things involve tracking non-text files. For example, game developers need to store large asset files, and AI developers need to store large model files.

Git is famously bad at handling large, binary files, but most people can't articulate why. Is it because version control as a concept just isn't compatible with them? Is it a conspiracy by Big Text to force you to keep your binary files outside of your repo? No, it's way more boring than that. I would give two main technical reasons:

1. Git is pretty bad at deltification (deduplicating files with a lot of data in common). Initially it doesn't try to at all -- it just stores each version of a file separately as "loose objects". Then, at various points, it tries to combine them into pack files that have a very idiosyncratic delta scheme.

2. Git always compresses objects with zlib, regardless of whether it helps. While zlib is great at compressing text files, it often will cause binary files to become *larger*. This is especially true for formats that are already compressed, like audio and video files.

The above issues were very straight-forward to solve in xit:

1. When an object is added to xit, it immediately splits it into chunks using FastCDC, a content-defined chunking algorithm. By chunking files, they are immediately being deduplicated because only the chunks that changed need to be saved internally. This is pretty much what every backup program on the planet does, so there is no innovation going on here, but that won't stop me from pretending there is.

2. A chunk is only stored with compression if it helps. Each chunk record begins with a byte marking its compression type (if it is 0, the chunk is uncompressed; if it is 1, it is zlib-compressed; other algorithms can be accomodated later), followed by a checksum of the uncompressed data.

Currently, the the max chunk size is 64k. It is likely that xit will eventually vary max chunk size based on the size of the file, so really large files can be stored with larger chunk sizes.

All chunks are stored in a single append-only file called the chunk store, located at `.xit/chunks`. It is a xitdb file containing a map of chunk hash -> chunk record. A chunk store can even be shared by multiple repos, deduplicating chunks across all of them. To do that, replace `.xit/chunks` with a symlink to a common store file.

It's important to note that xit only does chunking locally. When you push to a git host, they will likely store your objects in a standard git repo, and thus will still have performance problems with large files. You won't see the full benefit of this design until there is a host that stores objects the way xit does.
